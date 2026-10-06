import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from copy import deepcopy
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("public_qa", ROOT / "scripts/train-public-qa.py")
qa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qa)


class Tokenizer:
    eos_token_id = 2
    pad_token_id = 0
    def apply_chat_template(self, messages, **_):
        return json.dumps(messages, ensure_ascii=False) + "<think>"
    def encode(self, text, **_):
        return [ord(c) + 3 for c in text]


def row(number=0, split="train"):
    context = "앞 문장입니다. " * 300 + "정답 문구" + " 뒤 문장입니다." * 300
    start = context.index("정답 문구")
    answers = [{"text": "정답 문구", "answer_start": start}]
    return {"id": f"qa-{number}", "split": split, "upstreamSplit": "train", "upstreamRevision": qa.REVISION, "familyId": f"family-{number}", "upstreamAnnotation": {"kind": "human_authored_question_answer_spans"}, "sourceLicense": "CC-BY-SA-4.0", "localHumanReviewPerformed": False, "question": "문구는?", "context": context, "contextSha256": hashlib.sha256(context.encode()).hexdigest(), "answers": answers, "isImpossible": False, "originalQa": {"question": "문구는?", "answers": answers, "is_impossible": False}}


class PublicQaTrainingTests(unittest.TestCase):
    def test_training_stage_is_bound_to_the_closed_step_budget(self):
        self.assertEqual(qa.stage_for_max_steps(20), "public_qa_stage1")
        self.assertEqual(qa.stage_for_max_steps(40), "public_qa_stage2")
        for invalid in (True, 20.0, 19, 60):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "stage_budget_invalid"):
                qa.stage_for_max_steps(invalid)

    def test_context_window_retains_exact_answer_and_masks_prompt(self):
        encoded, receipt = qa.encode_row(Tokenizer(), row())
        self.assertEqual(len(encoded["input_ids"]), receipt["tokens"])
        self.assertLessEqual(receipt["tokens"], 1024)
        self.assertTrue(receipt["answerPreserved"])
        self.assertGreater(receipt["contextStart"], 0)
        supervised = "".join(chr(value - 3) for value in encoded["labels"] if value > 2)
        self.assertTrue(supervised.startswith("\n</think>\n"))
        self.assertEqual(json.loads(supervised.split("</think>\n", 1)[1]), {"answer": "정답 문구", "evidenceQuote": "정답 문구", "abstained": False})
        self.assertGreater(encoded["labels"].count(-100), 0)

    def test_impossible_answer_preserves_upstream_abstention(self):
        record = row()
        record.update(answers=[], isImpossible=True)
        self.assertEqual(qa.target(record), {"answer": "", "evidenceQuote": "", "abstained": True})
        self.assertTrue(qa.encode_row(Tokenizer(), record)[1]["answerPreserved"])

    def test_question_is_never_silently_truncated(self):
        record = row()
        record["question"] = "긴 질문" * 1000
        with self.assertRaisesRegex(ValueError, "exceed_token_budget"):
            qa.encode_row(Tokenizer(), record)

    def test_wrong_answer_offset_is_rejected(self):
        record = row()
        record["answers"][0]["answer_start"] = 0
        with self.assertRaisesRegex(ValueError, "answer_span_changed"):
            qa.encode_row(Tokenizer(), record)

    def test_public_provenance_and_family_admission(self):
        records = [row(i, "train" if i < 320 else "validation") for i in range(384)]
        with tempfile.TemporaryDirectory() as directory:
            data, manifest = Path(directory) / "data.jsonl", Path(directory) / "manifest.json"
            def save():
                data.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records), encoding="utf-8")
                manifest.write_text(json.dumps({"datasetSha256": qa.sha(data), "upstreamRevision": qa.REVISION, "license": "CC-BY-SA-4.0", "heldoutUsed": False, "counts": {"train": 320, "validation": 64}, "rowIds": [r["id"] for r in records]}), encoding="utf-8")
            save()
            self.assertEqual(len(qa.admission(data, manifest)[0]), 384)
            records[-1]["familyId"] = records[0]["familyId"]
            save()
            with self.assertRaisesRegex(ValueError, "family_leakage"):
                qa.admission(data, manifest)
            records[-1]["familyId"] = "unique"
            records[0]["localHumanReviewPerformed"] = True
            save()
            with self.assertRaisesRegex(ValueError, "annotation_provenance"):
                qa.admission(data, manifest)

    def test_no_standalone_host_training(self):
        with self.assertRaisesRegex(RuntimeError, "isolated_training_job_required"):
            qa.train(SimpleNamespace(), [], {})

    def test_encoding_preserves_selected_prompt_completion_and_eos_without_tail_padding(self):
        for impossible, expected_window in [(False, (2363, 3042)), (True, (0, 675))]:
            with self.subTest(impossible=impossible):
                record = row()
                if impossible:
                    record.update(answers=[], isImpossible=True)
                tokenizer = Tokenizer()
                encoded, receipt = qa.encode_row(tokenizer, record)
                self.assertEqual((receipt["contextStart"], receipt["contextEnd"]), expected_window)
                selected = record["context"][expected_window[0]:expected_window[1]]
                prompt = tokenizer.apply_chat_template([{"role": "system", "content": qa.SYSTEM}, {"role": "user", "content": json.dumps({"question": record["question"], "document": selected}, ensure_ascii=False)}], tokenize=False, add_generation_prompt=True)
                prefix = tokenizer.encode(prompt, add_special_tokens=False)
                completion = tokenizer.encode("\n</think>\n" + json.dumps(qa.target(record), ensure_ascii=False, separators=(",", ":")), add_special_tokens=False) + [tokenizer.eos_token_id]
                self.assertEqual(encoded, {"input_ids": prefix + completion, "attention_mask": [1] * (len(prefix) + len(completion)), "labels": [-100] * len(prefix) + completion})
                self.assertLess(len(encoded["input_ids"]), 1024)
                self.assertEqual(encoded["labels"][-1], tokenizer.eos_token_id)

    def test_single_row_batch_does_not_add_or_change_any_tokens(self):
        encoded, _ = qa.encode_row(Tokenizer(), row())
        before = deepcopy(encoded)
        self.assertEqual(qa.pad_batch([encoded], Tokenizer.pad_token_id), [before])
        self.assertEqual(encoded, before)

    def test_mixed_lengths_right_pad_only_batch_max_and_keep_real_eos_supervised(self):
        # Production sets pad_token_id == eos_token_id. Mask by padded position,
        # never by token equality, or the real completion EOS would lose its label.
        rows = [{"input_ids": [5, 6, 2], "attention_mask": [1, 1, 1], "labels": [-100, 6, 2]}, {"input_ids": [7, 8, 9, 10, 2], "attention_mask": [1] * 5, "labels": [-100, -100, 9, 10, 2]}]
        original = deepcopy(rows)
        padded = qa.pad_batch(rows, 2)
        self.assertEqual(padded[0], {"input_ids": [5, 6, 2, 2, 2], "attention_mask": [1, 1, 1, 0, 0], "labels": [-100, 6, 2, -100, -100]})
        self.assertEqual(padded[1], original[1])
        self.assertEqual(rows, original)

    def test_selective_loss_positions_follow_causal_shift_and_preserve_eos(self):
        encoded = {"input_ids": [5, 6, 9, 10, 2], "attention_mask": [1] * 5, "labels": [-100, -100, 9, 10, 2]}
        self.assertEqual(qa.supervised_causal_positions(encoded, 2), [1, 2, 3])
        self.assertEqual([encoded["labels"][position + 1] for position in qa.supervised_causal_positions(encoded, 2)], [9, 10, 2])

    def test_selective_positions_match_full_masked_loss_and_trainable_gradient(self):
        encoded = {"input_ids": [5, 6, 2, 3, 2], "attention_mask": [1] * 5, "labels": [-100, -100, 2, 3, 2]}
        weight, vocabulary = 0.07, 4

        def loss_and_gradient(positions, targets):
            losses, gradients = [], []
            for position, target in zip(positions, targets):
                scale = encoded["input_ids"][position]
                logits = [weight * scale * (token + 1) for token in range(vocabulary)]
                maximum = max(logits)
                exponentials = [math.exp(logit - maximum) for logit in logits]
                total = sum(exponentials)
                probabilities = [value / total for value in exponentials]
                losses.append(-(logits[target] - maximum - math.log(total)))
                gradients.append(scale * (sum(probability * (token + 1) for token, probability in enumerate(probabilities)) - (target + 1)))
            return sum(losses) / len(losses), sum(gradients) / len(gradients)

        shifted = encoded["labels"][1:] + [-100]
        full_positions = [position for position, target in enumerate(shifted) if target != -100]
        full_targets = [shifted[position] for position in full_positions]
        selective_positions = qa.supervised_causal_positions(encoded, 2)
        selective_targets = [encoded["labels"][position + 1] for position in selective_positions]
        full_loss, full_gradient = loss_and_gradient(full_positions, full_targets)
        selective_loss, selective_gradient = loss_and_gradient(selective_positions, selective_targets)
        self.assertEqual(selective_positions, full_positions)
        self.assertEqual(selective_targets, full_targets)
        self.assertAlmostEqual(selective_loss, full_loss, places=14)
        self.assertAlmostEqual(selective_gradient, full_gradient, places=14)

    def test_selective_loss_rejects_missing_holey_or_misaligned_completion_masks(self):
        invalid = [
            {"input_ids": [5, 6, 2], "attention_mask": [1, 1, 1], "labels": [-100, -100, -100]},
            {"input_ids": [5, 6, 2], "attention_mask": [1, 1, 1], "labels": [-100, 6, -100]},
            {"input_ids": [5, 6, 2], "attention_mask": [1, 1, 1], "labels": [-100, 7, 2]},
            {"input_ids": [5, 6, 2], "attention_mask": [1, 1, 0], "labels": [-100, 6, 2]},
            {"input_ids": [5, 6, 7], "attention_mask": [1, 1, 1], "labels": [-100, 6, 7]},
            {"input_ids": [5, 6, 2], "attention_mask": [1, 1, 1], "labels": [5, 6, 2]},
        ]
        for encoded in invalid:
            with self.subTest(encoded=encoded), self.assertRaisesRegex(ValueError, "selective_loss_(batch|mask)_invalid"):
                qa.supervised_causal_positions(encoded, 2)

    def test_collator_rejects_empty_oversized_or_misaligned_sequences(self):
        invalid = [[], [{"input_ids": [], "attention_mask": [], "labels": []}], [{"input_ids": [1] * 1025, "attention_mask": [1] * 1025, "labels": [1] * 1025}], [{"input_ids": [1, 2], "attention_mask": [1], "labels": [1, 2]}], [{"input_ids": [1, 2], "attention_mask": [1, 1], "labels": [1]}]]
        for features in invalid:
            with self.subTest(features_length=len(features)):
                with self.assertRaisesRegex(ValueError, "training_batch_sequence_invalid"):
                    qa.pad_batch(features, 2)


if __name__ == "__main__":
    unittest.main()
