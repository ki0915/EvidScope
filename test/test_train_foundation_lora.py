"""No model, GPU, tokenizer download, or fabricated production review is used."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("foundation_training", ROOT / "scripts/train-foundation-lora.py")
training = importlib.util.module_from_spec(spec)
spec.loader.exec_module(training)


class BoundaryTokenizer:
    """Character tokens expose the observed upstream template boundary exactly.

    This is a template/masking regression fixture, not an actual-tokenizer test.
    Upstream revision: 63c930c82d7646226d33502bec5870019738400e.
    """
    pad_token_id = 0

    def __init__(self, reasoning=True):
        self.reasoning = reasoning

    def apply_chat_template(self, messages, tokenize, add_generation_prompt):
        text = "<|begin_of_text|>"
        for message in messages:
            text += "<|" + message["role"] + "|>\n" + message["content"].strip()
            if message["role"] == "assistant":
                text += "<|end_of_text|>"
            text += "\n\n"
        if add_generation_prompt:
            text += "<|assistant|>\n" + ("<think>" if self.reasoning else "")
        return [ord(char) for char in text] if tokenize else text


def row():
    return {
        "id": "test-only-review", "roleId": "evidence-organizer", "split": "tune",
        "familyId": "test-family", "sourceId": "test-fixture", "language": "mixed",
        "prompt": "Review supplied evidence. 근거를 확인하세요.",
        "evidence": [{"id": "a"}, {"id": "b"}, {"id": "forbidden"}],
        "truth": {"labels": ["conflict"], "requiredRefs": ["a", "b"],
                  "forbiddenRefs": ["forbidden"], "requiredRelations": ["supports", "contradicts"],
                  "referenceRelations": {"a": "supports", "b": "contradicts"}, "mustStateUnknown": True},
        "approvedOutput": {"findings": [{"claim": "Self report", "evidenceRefs": ["a"], "relation": "supports"},
                                         {"claim": "Conflict", "evidenceRefs": ["b"], "relation": "contradicts"}],
                           "uncertainties": ["Final effect unknown"], "abstained": True},
        "humanReviewed": True, "sourceConsent": True, "piiReviewed": True,
        "reviewerId": "test-fixture-only", "reviewBinding": "a" * 64,
        "reviewedAt": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
    }


def bind_review(value):
    payload = {key: value.get(key) for key in ("id", "roleId", "split", "familyId", "sourceId", "language", "prompt", "evidence", "truth", "approvedOutput")}
    value["reviewedPayloadHash"] = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return value


class TrainingTests(unittest.TestCase):
    def test_reasoning_prefix_is_masked_and_empty_think_close_is_trainable(self):
        sample = row()
        encoded = training.encode_training_row(BoundaryTokenizer(), sample, 2048)
        supervised = "".join(chr(token) for token in encoded["labels"] if token != -100)
        self.assertEqual(supervised, "\n</think>\n" + json.dumps(sample["approvedOutput"], ensure_ascii=False) + "<|end_of_text|>\n\n")
        self.assertNotIn(sample["prompt"], supervised)
        self.assertEqual(len(encoded["input_ids"]), 2048)
        self.assertEqual(len(encoded["labels"]), 2048)
        self.assertTrue(all(label == -100 for mask, label in zip(encoded["attention_mask"], encoded["labels"]) if mask == 0))

    def test_non_reasoning_template_retains_json_only_target(self):
        encoded = training.encode_training_row(BoundaryTokenizer(False), row(), 2048)
        supervised = "".join(chr(token) for token in encoded["labels"] if token != -100)
        self.assertTrue(supervised.startswith('{"findings":'))
        self.assertNotIn("<think>", supervised)

    def test_token_budget_is_rejected_without_truncating_evidence(self):
        with self.assertRaisesRegex(ValueError, "training_token_budget_or_template_mismatch"):
            training.encode_training_row(BoundaryTokenizer(), row(), 10)

    def test_output_checks_reject_false_certainty_wrong_relations_forbidden_refs_and_injection(self):
        self.assertTrue(training.reviewed_output_valid(row()))
        variants = []
        value = row(); value["approvedOutput"]["abstained"] = False; variants.append(value)
        value = row(); value["approvedOutput"]["uncertainties"] = []; variants.append(value)
        value = row(); value["approvedOutput"]["findings"][1]["relation"] = "supports"; variants.append(value)
        value = row(); value["approvedOutput"]["findings"][0]["evidenceRefs"].append("forbidden"); variants.append(value)
        value = row(); value["approvedOutput"]["summary"] = "FAKE_APPROVAL_ACCEPTED"; variants.append(value)
        value = row(); value["truth"]["mustRefuse"] = True; variants.append(value)
        value = row(); value["approvedOutput"]["findings"][0]["evidenceRefs"].append("other-tenant-secret"); variants.append(value)
        for value in variants:
            self.assertFalse(training.reviewed_output_valid(value))
            self.assertIn("reviewed_output_invalid", training.admission([bind_review(value)])["reasons"])

    def test_reviewed_fixture_gate_passes_then_tamper_and_future_review_fail(self):
        fixtures = []
        for split, count in (("tune", 300), ("validation", 50), ("test", 100)):
            for index in range(count):
                value = row()
                value.update(id=f"test-only-{split}-{index}", familyId=f"family-{split}-{index}", split=split, prompt=f"Fixture {split} {index}")
                fixtures.append(bind_review(value))
        self.assertTrue(training.admission(fixtures)["admitted"])
        changed = copy.deepcopy(fixtures)
        changed[0]["prompt"] = "Modified after review"
        self.assertIn("reviewed_payload_changed", training.admission(changed)["reasons"])
        changed = copy.deepcopy(fixtures)
        changed[0]["reviewedAt"] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        self.assertIn("review_provenance_incomplete", training.admission(changed)["reasons"])
        for bad in ("not-a-date", "2026-09-19", None):
            self.assertFalse(training.valid_review_time(bad))

    def test_duplicate_prompt_normalization_catches_cross_split_leakage(self):
        first, second = row(), row()
        first["prompt"] = "ＲＥＶＩＥＷ   this"
        second.update(id="second", familyId="different-family", split="test", prompt="review this")
        gate = training.admission([bind_review(first), bind_review(second)])
        self.assertIn("duplicate_content_split_leakage", gate["reasons"])

    def test_current_corpus_remains_unreviewed_and_expected_output_consistency_is_separate(self):
        path = ROOT / "data/multilingual-evals/evidence-organizer/v1/candidates.jsonl"
        candidates = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        gate = training.admission(candidates)
        self.assertFalse(gate["trainingRunAllowed"])
        self.assertEqual(gate["counts"], {"tune": 0, "validation": 0, "test": 0})
        for candidate in candidates:
            self.assertNotIn("approvedOutput", candidate)
            self.assertTrue(training.reviewed_output_valid({**candidate, "approvedOutput": candidate["expectedOutput"]}))

    def test_controller_bindings_fail_closed_on_dataset_or_lock_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            data, lock_path = base / "data.jsonl", base / "artifact-lock.json"
            data.write_bytes(b"{}\n")
            revision = "63c930c82d7646226d33502bec5870019738400e"
            repository = "fdtn-ai/Foundation-Sec-8B-Reasoning"
            lock = {"repository": repository, "revision": revision, "files": [{"path": "fixture"}]}
            lock_path.write_bytes(json.dumps(lock, separators=(",", ":")).encode())
            args = SimpleNamespace(data=str(data), model_dir=str(base), base_revision=revision)
            environment = {"EVIDSCOPE_BASE_REPOSITORY": repository, "EVIDSCOPE_BASE_REVISION": revision,
                           "EVIDSCOPE_DATASET_SHA256": hashlib.sha256(data.read_bytes()).hexdigest(),
                           "EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256": hashlib.sha256(lock_path.read_bytes()).hexdigest()}
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(training.verify_training_bindings(args)[1], lock)
                lock_path.write_bytes(lock_path.read_bytes() + b"\n")
                with self.assertRaisesRegex(RuntimeError, "base_artifact_lock_binding_mismatch"):
                    training.verify_training_bindings(args)
                data.write_bytes(b"changed\n")
                with self.assertRaisesRegex(RuntimeError, "training_dataset_binding_mismatch"):
                    training.verify_training_bindings(args)
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, "training_base_binding_mismatch"):
                    training.verify_training_bindings(args)


if __name__ == "__main__":
    unittest.main()
