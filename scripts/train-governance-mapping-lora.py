"""QLoRA training of the governance-mapping adapter (docs/governance-model.md). No downloads, adapter only, no promotion.

Input rows come from `node scripts/governance-mapping.mjs training-set`: the exact prompt the runtime sends (system + user
messages with the retrieved catalog candidates) and the gold JSON as the target. The base is the safetensors release of the
runtime model, fdtn-ai/Foundation-Sec-1.1-8B-Instruct, so the adapter applies to the pinned Q4_K_M GGUF after conversion
with llama.cpp convert_lora_to_gguf.py. Merged weights are never written.
--check-only and --token-check run without GPU libraries; training needs the isolated container (EVIDSCOPE_ISOLATED=1).
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sys
from functools import partial

sys.path.insert(0, str(Path(__file__).resolve().parent))
from training_artifacts import atomic_json, seal_checkpoint, verify_checkpoint, seal_candidate, sha256_file

BASE_REPOSITORY = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
TASK = "governance-mapping"
RELATIONS = {"supports", "contradicts", "context_only"}
CONFIDENCE = {"low", "medium", "high"}
# r=8 on every linear projection; with completion-only logits this is sized for the 12 GB card under the 0.65 memory fraction.
RECIPE = {"rank": 8, "alpha": 16, "dropout": 0.05, "targetModules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
          "sequenceLength": 1536, "batchSize": 1, "gradientAccumulationSteps": 8, "epochs": 2, "learningRatePerMillion": 200, "warmupStepsPer1000": 30,
          "seed": 42, "saveSteps": 5}


def load_helper(name, file_name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file_name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_target(text):
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return False
    if not isinstance(value, dict) or set(value) != {"abstain", "mappings"} or not isinstance(value["abstain"], bool) or not isinstance(value["mappings"], list):
        return False
    seen = set()
    for item in value["mappings"]:
        if not isinstance(item, dict) or set(item) != {"requirementId", "relation", "evidenceLocator", "confidence"}:
            return False
        if not isinstance(item["requirementId"], str) or item["requirementId"] in seen or item["relation"] not in RELATIONS or item["confidence"] not in CONFIDENCE:
            return False
        seen.add(item["requirementId"])
    return value["abstain"] == (len(value["mappings"]) == 0) and len(value["mappings"]) <= 5


def admission(path):
    """Re-checks what the node admission already decided; the held-out test split never reaches this file."""
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    reasons, ids, families, digests = [], set(), {}, set()
    for row in rows:
        if row.get("task") != TASK or row.get("taskVersion") != 1 or row.get("roleId") != "governance-assistant":
            reasons.append("task_invalid")
        if row.get("split") not in ("tune", "validation"):
            reasons.append("split_invalid_or_test_present")
        if row.get("id") in ids or not isinstance(row.get("id"), str):
            reasons.append("record_identity_invalid")
        ids.add(row.get("id"))
        families.setdefault(row.get("familyId"), set()).add(row.get("split"))
        digests.add(row.get("catalogDigest"))
        messages = row.get("messages")
        if not isinstance(messages, list) or len(messages) != 2 or [m.get("role") for m in messages] != ["system", "user"] or not all(isinstance(m.get("content"), str) for m in messages):
            reasons.append("messages_invalid")
        if not valid_target(row.get("target")):
            reasons.append("target_invalid")
        if row.get("labelSource") not in ("derived_mapping_table", "claude_drafted") or (row.get("labelSource") == "claude_drafted" and not re.fullmatch(r"[a-f0-9]{64}", str(row.get("reviewedPayloadHash")))):
            reasons.append("label_provenance_invalid")
    if any(len(splits) > 1 for splits in families.values()):
        reasons.append("family_split_leakage")
    if len(digests) != 1:
        reasons.append("catalog_digest_mixed")
    counts = {split: sum(row.get("split") == split for row in rows) for split in ("tune", "validation")}
    if counts["tune"] < 300 or counts["validation"] < 50:
        reasons.append("eligible_counts_below_policy")
    reasons = sorted(set(reasons))
    return rows, {"admitted": not reasons, "counts": counts, "reasons": reasons, "qualityClaimAllowed": False}


def encode_row(tokenizer, row, sequence_length=RECIPE["sequenceLength"]):
    """Prompt tokens are masked; the loss covers the gold JSON and EOS only."""
    prefix = tokenizer.apply_chat_template(row["messages"], tokenize=False, add_generation_prompt=True)
    completion = ("\n</think>\n" if prefix.rstrip().endswith("<think>") else "") + row["target"]
    prefix_ids = tokenizer.encode(prefix, add_special_tokens=False)
    answer_ids = tokenizer.encode(completion, add_special_tokens=False) + [tokenizer.eos_token_id]
    full = prefix_ids + answer_ids
    if len(full) > sequence_length:
        raise ValueError("training_row_exceeds_sequence_length:" + row["id"])
    return {"input_ids": full, "attention_mask": [1] * len(full), "labels": [-100] * len(prefix_ids) + answer_ids}


def verify_bindings(args):
    """Binds the container inputs to the digests the controller inspected; every base file is re-hashed."""
    if not re.fullmatch(r"[a-f0-9]{40}", args.base_revision or ""):
        raise RuntimeError("base_revision_required")
    if os.environ.get("EVIDSCOPE_BASE_REPOSITORY") != BASE_REPOSITORY or os.environ.get("EVIDSCOPE_BASE_REVISION") != args.base_revision:
        raise RuntimeError("training_base_binding_mismatch")
    for name in ("EVIDSCOPE_DATASET_SHA256", "EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256"):
        if not re.fullmatch(r"[a-f0-9]{64}", os.environ.get(name, "")):
            raise RuntimeError("training_digest_binding_required")
    if sha256_file(args.data) != os.environ["EVIDSCOPE_DATASET_SHA256"]:
        raise RuntimeError("training_dataset_binding_mismatch")
    root = Path(args.model_dir).resolve()
    if sha256_file(root / "artifact-lock.json") != os.environ["EVIDSCOPE_BASE_ARTIFACT_LOCK_SHA256"]:
        raise RuntimeError("base_artifact_lock_binding_mismatch")
    lock = json.loads((root / "artifact-lock.json").read_text(encoding="utf-8"))
    if lock.get("repository") != BASE_REPOSITORY or lock.get("revision") != args.base_revision or not lock.get("files"):
        raise RuntimeError("base_artifact_lock_required")
    checked = set()
    for item in lock["files"]:
        file = (root / item["path"]).resolve()
        if not file.is_relative_to(root) or file.is_symlink() or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")) or sha256_file(file) != item["sha256"]:
            raise RuntimeError("base_artifact_digest_mismatch")
        checked.add(item["path"])
    if not {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"} <= checked:
        raise RuntimeError("base_artifact_files_missing")
    if not set(json.loads((root / "model.safetensors.index.json").read_text())["weight_map"].values()) <= checked:
        raise RuntimeError("base_weight_shard_unverified")
    return root


def identity_for(args, root):
    here = Path(__file__)
    return {"task": TASK, "baseRepository": BASE_REPOSITORY, "baseRevision": args.base_revision, "baseArtifactLockSha256": sha256_file(root / "artifact-lock.json"),
            "datasetSha256": sha256_file(args.data), "trainerSha256": sha256_file(here), "artifactHelperSha256": sha256_file(here.with_name("training_artifacts.py")),
            "collateHelperSha256": sha256_file(here.with_name("train-public-qa.py")), "kbitHelperSha256": sha256_file(here.with_name("public-qa-kbit.py")),
            "image": os.environ.get("EVIDSCOPE_TRAINING_IMAGE", ""), "gpuMemoryFractionPercent": round(args.gpu_memory_fraction * 100), **RECIPE}


def check_output(args):
    output = Path(args.output).resolve()
    if not output.is_relative_to(Path("/checkpoints").resolve()) or output == Path("/checkpoints").resolve():
        raise RuntimeError("training_output_path_invalid")
    if args.resume_from_checkpoint:
        resume = Path(args.resume_from_checkpoint).resolve()
        if not resume.is_relative_to(output) or not re.fullmatch(r"checkpoint-[1-9][0-9]*", resume.name):
            raise RuntimeError("checkpoint_path_invalid")
    elif output.exists() and any(output.iterdir()):
        raise RuntimeError("training_output_must_be_new")
    return output


def train(args, rows):
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise RuntimeError("isolated_training_job_required")
    if not 0.1 <= args.gpu_memory_fraction <= 0.65:
        raise RuntimeError("gpu_memory_fraction_invalid")
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", WANDB_DISABLED="true", TOKENIZERS_PARALLELISM="false")
    root = verify_bindings(args)
    identity = identity_for(args, root)
    # A registry digest (repo@sha256:...) or the local image ID the Docker launcher verified with `docker inspect`.
    if not re.fullmatch(r"(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}", identity["image"]):
        raise RuntimeError("training_image_binding_required")
    output = check_output(args)
    if args.resume_from_checkpoint:
        verify_checkpoint(Path(args.resume_from_checkpoint).resolve(), identity)
    output.mkdir(parents=True, exist_ok=True)
    collate = load_helper("governance_collate", "train-public-qa.py")
    kbit = load_helper("governance_kbit", "public-qa-kbit.py")
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, Trainer, TrainingArguments, TrainerCallback
    from peft import LoraConfig, get_peft_model
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
    tokenizer.pad_token = tokenizer.eos_token
    # Reject an over-long row before the model takes VRAM.
    tune = [encode_row(tokenizer, row) for row in rows if row["split"] == "tune"]
    validation = [encode_row(tokenizer, row) for row in rows if row["split"] == "validation"]
    if not torch.cuda.is_available():
        raise RuntimeError("training_gpu_unavailable")
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(args.gpu_memory_fraction, 0)
    torch.manual_seed(RECIPE["seed"])
    torch.cuda.reset_peak_memory_stats()
    model = AutoModelForCausalLM.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False, device_map={"": 0}, torch_dtype=torch.float16,
                                                 attn_implementation="sdpa", quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                 bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16))
    model = kbit.prepare_memory_efficient_kbit(model)
    torch.cuda.empty_cache()
    model = get_peft_model(model, LoraConfig(r=RECIPE["rank"], lora_alpha=RECIPE["alpha"], lora_dropout=RECIPE["dropout"], target_modules=RECIPE["targetModules"],
                                             bias="none", task_type="CAUSAL_LM"))
    model.config.use_cache = False
    stop = {"requested": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(requested=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(requested=True))

    class Checkpoints(TrainerCallback):
        def on_step_end(self, arguments, state, control, **_):
            print(json.dumps({"optimizerStep": state.global_step, "cudaPeakAllocatedMiB": round(torch.cuda.max_memory_allocated() / 1048576)}), flush=True)
            if stop["requested"]:
                control.should_save = True
                control.should_training_stop = True
            return control

        def on_save(self, arguments, state, control, **_):
            seal_checkpoint(Path(arguments.output_dir) / f"checkpoint-{state.global_step}", identity, state.global_step)
            return control

    settings = TrainingArguments(output_dir=str(output), num_train_epochs=RECIPE["epochs"], per_device_train_batch_size=1, per_device_eval_batch_size=1,
                                 gradient_accumulation_steps=RECIPE["gradientAccumulationSteps"], gradient_checkpointing=True,
                                 learning_rate=RECIPE["learningRatePerMillion"] / 1e6, warmup_ratio=RECIPE["warmupStepsPer1000"] / 1000, lr_scheduler_type="cosine",
                                 fp16=True, report_to=[], save_strategy="steps", save_steps=RECIPE["saveSteps"], save_total_limit=2, eval_strategy="epoch",
                                 logging_strategy="no", seed=RECIPE["seed"], data_seed=RECIPE["seed"], dataloader_num_workers=0, dataloader_pin_memory=False,
                                 remove_unused_columns=False)
    # The held-out test split is never loaded here; validation loss is a training diagnostic, not a quality measurement.
    trainer = Trainer(model=model, args=settings, train_dataset=tune, eval_dataset=validation,
                      data_collator=partial(collate.collate_rows, pad_token_id=tokenizer.eos_token_id), callbacks=[Checkpoints()])
    result = trainer.train(resume_from_checkpoint=args.resume_from_checkpoint or None)
    if stop["requested"]:
        raise SystemExit(75)
    collate.verify_finite_adapter(model, torch)
    candidate = output / "candidate"
    model.save_pretrained(candidate, safe_serialization=True)
    if any(path.name.startswith("model") and path.suffix == ".safetensors" for path in candidate.iterdir()):
        raise RuntimeError("merged_weights_forbidden")
    metrics = {**result.metrics, "cudaPeakAllocatedMiB": round(torch.cuda.max_memory_allocated() / 1048576)}
    receipt = {"schemaVersion": 2, "status": "trained_candidate", "identity": identity, "globalStep": trainer.state.global_step, "trainingMetrics": metrics,
               "trainingRunCompleted": True, "heldOutTestUsedForTraining": False, "qualityClaimAllowed": False, "promotionAllowed": False,
               "next": "convert with llama.cpp convert_lora_to_gguf.py, evaluate with scripts/governance_mapping_batch.py, gate with scripts/governance-mapping.mjs"}
    atomic_json(candidate / "training-receipt.json", receipt)
    seal_candidate(candidate, identity, trainer.state.global_step, metrics)
    print(json.dumps(receipt, ensure_ascii=False), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--token-check", action="store_true")
    parser.add_argument("--model-dir", default="/models/base")
    parser.add_argument("--base-revision", default="")
    parser.add_argument("--output", default="/checkpoints/governance-mapping/run")
    parser.add_argument("--gpu-memory-fraction", type=float, default=0.65)
    parser.add_argument("--resume-from-checkpoint")
    args = parser.parse_args(argv)
    rows, gate = admission(args.data)
    print(json.dumps(gate), flush=True)
    if not gate["admitted"]:
        return 2
    if args.token_check:
        os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
        lengths = [len(encode_row(tokenizer, row)["input_ids"]) for row in rows]
        print(json.dumps({"tokenCheckPassed": True, "rows": len(lengths), "maxTokens": max(lengths), "sequenceLength": RECIPE["sequenceLength"]}), flush=True)
    elif not args.check_only:
        train(args, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
