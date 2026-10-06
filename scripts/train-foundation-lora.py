"""Offline QLoRA candidate training. No downloads; no automatic promotion.
Gate data and exit without heavyweight imports using --check-only.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unicodedata
import signal

sys.path.insert(0, str(Path(__file__).resolve().parent))
from training_artifacts import atomic_json, seal_checkpoint, verify_checkpoint, seal_candidate, canonical_hash, sha256_file


def file_sha256(path):
    return sha256_file(path)


def valid_review_time(value):
    if not isinstance(value, str):
        return False
    try:
        reviewed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return reviewed_at.tzinfo is not None and reviewed_at <= datetime.now(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return False


def reviewed_output_valid(row):
    """Mirror role-evaluation.mjs deterministic requirements, not semantic review."""
    output, truth, evidence = row.get("approvedOutput"), row.get("truth"), row.get("evidence")
    if not isinstance(output, dict) or not isinstance(truth, dict) or not isinstance(evidence, list):
        return False
    findings = output.get("findings", [])
    required, forbidden = truth.get("requiredRefs"), truth.get("forbiddenRefs", [])
    required_relations, reference_relations = truth.get("requiredRelations", []), truth.get("referenceRelations", {})
    if not all(isinstance(value, list) for value in (findings, required, forbidden, required_relations)) or not isinstance(reference_relations, dict):
        return False
    if not isinstance(truth.get("labels"), list) or not truth["labels"]:
        return False
    if any(not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in evidence):
        return False
    if any(not isinstance(finding, dict) or not isinstance(finding.get("evidenceRefs", []), list) for finding in findings):
        return False
    cited_list = [ref for finding in findings for ref in finding.get("evidenceRefs", [])]
    relations_list = [finding.get("relation") for finding in findings]
    if any(not isinstance(ref, str) for ref in cited_list + required + forbidden) or any(not isinstance(relation, str) for relation in relations_list + required_relations):
        return False
    cited, known, relations = set(cited_list), {item["id"] for item in evidence}, set(relations_list)
    if not set(required) <= cited or not cited <= known or cited.intersection(forbidden) or "other-tenant-secret" in cited:
        return False
    if not set(required_relations) <= relations or any(not any(ref in f.get("evidenceRefs", []) and f.get("relation") == relation for f in findings) for ref, relation in reference_relations.items()):
        return False
    uncertainties = output.get("uncertainties", [])
    if truth.get("mustStateUnknown"):
        if not isinstance(uncertainties, list) or not uncertainties or output.get("abstained") is not True:
            return False
    elif output.get("abstained") is not False:
        return False
    if truth.get("mustRefuse") and (output.get("abstained") is not True or findings):
        return False
    return "FAKE_APPROVAL_ACCEPTED" not in json.dumps(output, ensure_ascii=False)


def encode_training_row(tokenizer, row, sequence_length):
    messages = [{"role": "system", "content": "근거만 인용하고 불확실성을 밝혀라. Return JSON advisory only; do not decide approval or legal compliance."}, {"role": "user", "content": json.dumps({"request": row["prompt"], "evidence": row["evidence"]}, ensure_ascii=False)}]
    rendered_prefix = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    answer = json.dumps(row["approvedOutput"], ensure_ascii=False)
    # The pinned Reasoning template opens <think> in its generation prefix.
    # Close that block without inventing a reasoning trace before the reviewed JSON.
    if rendered_prefix.rstrip().endswith("<think>"):
        answer = "<think>\n</think>\n" + answer
    prefix = tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True)
    full = tokenizer.apply_chat_template(messages + [{"role": "assistant", "content": answer}], tokenize=True, add_generation_prompt=False)
    if len(full) > sequence_length or full[:len(prefix)] != prefix:
        raise ValueError("training_token_budget_or_template_mismatch")
    pad = sequence_length - len(full)
    return {"input_ids": full + [tokenizer.pad_token_id] * pad, "attention_mask": [1] * len(full) + [0] * pad, "labels": [-100] * len(prefix) + full[len(prefix):] + [-100] * pad}


def verify_training_bindings(args):
    """Bind the offline Pod inputs to the controller's inspected bytes."""
    repository = "fdtn-ai/Foundation-Sec-8B-Reasoning"
    if not re.fullmatch(r"[a-f0-9]{40}", args.base_revision):
        raise RuntimeError("base_revision_required")
    if os.environ.get("EVIDSCOPE_BASE_REPOSITORY") != repository or os.environ.get("EVIDSCOPE_BASE_REVISION") != args.base_revision:
        raise RuntimeError("training_base_binding_mismatch")
    for name in ("EVIDSCOPE_DATASET_SHA256", "EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256"):
        if not re.fullmatch(r"[a-f0-9]{64}", os.environ.get(name, "")):
            raise RuntimeError("training_digest_binding_required")
    if file_sha256(args.data) != os.environ["EVIDSCOPE_DATASET_SHA256"]:
        raise RuntimeError("training_dataset_binding_mismatch")
    root = Path(args.model_dir).resolve()
    lock_path = root / "artifact-lock.json"
    if file_sha256(lock_path) != os.environ["EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256"]:
        raise RuntimeError("base_artifact_lock_binding_mismatch")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("repository") != repository or lock.get("revision") != args.base_revision or not lock.get("files"):
        raise RuntimeError("base_artifact_lock_required")
    return root, lock

def admission(records, role="evidence-organizer"):
    rows = [r for r in records if r.get("roleId") == role]
    counts = {s: sum(r.get("split") == s and r.get("humanReviewed") is True for r in rows) for s in ("tune", "validation", "test")}
    reasons, families, fingerprints, identities = [], {}, {}, set()
    for split, minimum in (("tune", 300), ("validation", 50), ("test", 100)):
        if counts[split] < minimum:
            reasons.append(f"human-reviewed {split} {counts[split]}/{minimum}")
    for r in rows:
        if r.get("id") in identities or not r.get("id"):
            reasons.append("record_identity_invalid")
        identities.add(r.get("id"))
        if r.get("humanReviewed") is not True or r.get("sourceConsent") is not True or r.get("piiReviewed") is not True or not all(isinstance(r.get(k), str) and r[k].strip() for k in ("reviewerId", "sourceId", "familyId", "language")) or not valid_review_time(r.get("reviewedAt")) or not re.fullmatch(r"[a-f0-9]{64}", str(r.get("reviewBinding", ""))):
            reasons.append("review_provenance_incomplete")
        if r.get("split") not in counts:
            reasons.append("split_invalid")
        family = r.get("familyId")
        families.setdefault(family, set()).add(r.get("split"))
        prompt = r.get("prompt")
        if isinstance(prompt, str):
            prompt = " ".join(unicodedata.normalize("NFKC", prompt).split()).lower()
        fingerprint = hashlib.sha256(json.dumps({"prompt": prompt, "evidence": r.get("evidence")}, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        fingerprints.setdefault(fingerprint, set()).add(r.get("split"))
        payload = {k: r.get(k) for k in ("id", "roleId", "split", "familyId", "sourceId", "language", "prompt", "evidence", "truth", "approvedOutput")}
        try:
            if r.get("reviewedPayloadHash") != canonical_hash(payload):
                reasons.append("reviewed_payload_changed")
        except ValueError:
            reasons.append("canonical_numeric_format_unsupported")
        if not reviewed_output_valid(r):
            reasons.append("reviewed_output_invalid")
    if any(len(v) > 1 for v in families.values()):
        reasons.append("family_split_leakage")
    if any(len(v) > 1 for v in fingerprints.values()):
        reasons.append("duplicate_content_split_leakage")
    reasons = sorted(set(reasons))
    return {"admitted": not reasons, "trainingRunAllowed": not reasons, "qualityClaimAllowed": False, "counts": counts, "reasons": reasons}

def train(args, records):
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise RuntimeError("isolated_training_job_required")
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", WANDB_DISABLED="true")
    root, lock = verify_training_bindings(args)
    checked = set()
    for item in lock["files"]:
        file = (root / item["path"]).resolve()
        if not file.is_relative_to(root) or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")):
            raise RuntimeError("base_artifact_path_invalid")
        if file_sha256(file) != item["sha256"]:
            raise RuntimeError("base_artifact_digest_mismatch")
        checked.add(item["path"])
    if not {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"} <= checked:
        raise RuntimeError("base_artifact_files_missing")
    weight_map = json.loads((root / "model.safetensors.index.json").read_text())["weight_map"]
    if not set(weight_map.values()) <= checked:
        raise RuntimeError("base_weight_shard_unverified")
    identity = {"baseRepository": "fdtn-ai/Foundation-Sec-8B-Reasoning", "baseRevision": args.base_revision, "baseArtifactLockSha256": file_sha256(root / "artifact-lock.json"), "datasetSha256": file_sha256(args.data), "trainerSha256": file_sha256(__file__), "artifactHelperSha256": file_sha256(Path(__file__).with_name("training_artifacts.py")), "image": os.environ.get("EVIDSCOPE_TRAINING_IMAGE", ""), "rank": 8, "sequenceLength": args.sequence_length, "gpuMemoryFraction": args.gpu_memory_fraction, "batchSize": 1, "gradientAccumulationSteps": 16, "seed": 42, "learningRate": 0.0001}
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", identity["image"]):
        raise RuntimeError("training_image_binding_required")
    if args.resume_from_checkpoint:
        resume = Path(args.resume_from_checkpoint).resolve()
        if not resume.is_relative_to(Path("/checkpoints").resolve()):
            raise RuntimeError("checkpoint_path_invalid")
        verify_checkpoint(resume, identity)
    output = Path(args.output)
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("training_output_must_be_new")
    try:
        os.nice(10)
    except OSError:
        pass
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, Trainer, TrainingArguments, TrainerCallback, default_data_collator
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
    tokenizer.pad_token = tokenizer.eos_token
    # Reject a template or sequence-budget mismatch before allocating model VRAM.
    train_set = [encode_training_row(tokenizer, r, args.sequence_length) for r in records if r["roleId"] == args.role and r["split"] == "tune"]
    validation = [encode_training_row(tokenizer, r, args.sequence_length) for r in records if r["roleId"] == args.role and r["split"] == "validation"]
    if not torch.cuda.is_available():
        raise RuntimeError("training_gpu_unavailable")
    if not 0.1 <= args.gpu_memory_fraction <= 0.65:
        raise RuntimeError("gpu_memory_fraction_invalid")
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(args.gpu_memory_fraction, 0)
    torch.manual_seed(42)
    model = AutoModelForCausalLM.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False, device_map={"": 0}, quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16))
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    model = get_peft_model(model, LoraConfig(r=8, lora_alpha=16, lora_dropout=0.05, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"], bias="none", task_type="CAUSAL_LM"))
    model.config.use_cache = False
    # The held-out test partition is never passed into Trainer.
    stopping = {"requested": False}
    def stop_requested(*_):
        stopping["requested"] = True
    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    class CompleteCheckpoint(TrainerCallback):
        def on_step_end(self, arguments, state, control, **_):
            if stopping["requested"]:
                control.should_save = True
                control.should_training_stop = True
            return control
        def on_save(self, arguments, state, control, **_):
            seal_checkpoint(Path(arguments.output_dir) / f"checkpoint-{state.global_step}", identity, state.global_step)
            return control
    settings = TrainingArguments(output_dir=args.output, num_train_epochs=1, per_device_train_batch_size=1, per_device_eval_batch_size=1, gradient_accumulation_steps=16, gradient_checkpointing=True, learning_rate=0.0001, fp16=True, report_to=[], save_strategy="steps", save_steps=10, eval_strategy="epoch", logging_strategy="no", save_total_limit=2, seed=42, data_seed=42, dataloader_num_workers=0, dataloader_pin_memory=False)
    trainer = Trainer(model=model, args=settings, train_dataset=train_set, eval_dataset=validation, data_collator=default_data_collator, callbacks=[CompleteCheckpoint()])
    trained = trainer.train(resume_from_checkpoint=args.resume_from_checkpoint or None)
    if stopping["requested"]:
        raise SystemExit(75)
    candidate = output / "candidate"
    model.save_pretrained(candidate, safe_serialization=True)
    tokenizer.save_pretrained(candidate)
    receipt = {"schemaVersion": 2, "status": "trained_candidate", "identity": identity, "globalStep": trainer.state.global_step, "trainingMetrics": trained.metrics, "baseRevision": args.base_revision, "datasetSha256": file_sha256(args.data), "rank": 8, "sequenceLength": args.sequence_length, "gpuMemoryFraction": args.gpu_memory_fraction, "cpuThreads": 2, "targetFormat": "reviewed_json_with_empty_reasoning_block_when_required_by_template", "trainingRunCompleted": True, "qualityClaimAllowed": False, "promotionAllowed": False, "heldOutTestUsedForTraining": False}
    atomic_json(candidate / "training-receipt.json", receipt)
    seal_candidate(candidate, identity, trainer.state.global_step, trained.metrics)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--role", default="evidence-organizer")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--model-dir", default="/models/foundation-base")
    parser.add_argument("--base-revision", default="")
    parser.add_argument("--output", default="/checkpoints/candidate")
    parser.add_argument("--sequence-length", type=int, choices=(1024, 2048), default=1024)
    parser.add_argument("--gpu-memory-fraction", type=float, default=0.65)
    parser.add_argument("--resume-from-checkpoint")
    args = parser.parse_args()
    records = [json.loads(line) for line in Path(args.data).read_text(encoding="utf-8").splitlines() if line.strip()]
    gate = admission(records, args.role)
    print(json.dumps(gate))
    if not gate["admitted"]:
        return 2
    if not args.check_only:
        train(args, records)
    return 0

if __name__ == "__main__":
    sys.exit(main())
