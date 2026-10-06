"""Offline Kubernetes-only QLoRA on original, publicly human-annotated KLUE QA.

This bounded stage trains extraction/citation formatting, not governance decisions.
Check-only uses the Python standard library; token-check additionally loads the
local tokenizer on CPU and proves that every selected answer survives encoding.
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

REVISION = "3efd98708a40ff49251fddde35453f8fbb11f536"
SYSTEM = "제공된 문서에서 질문의 답을 그대로 인용하세요. JSON으로 answer, evidenceQuote, abstained를 반환하세요. 문서에 답이 없으면 answer와 evidenceQuote는 빈 문자열, abstained는 true입니다."


def grounding_helper(stage=None):
    name = "public_qa_grounding_continuation" if stage == "public_qa_grounding_continuation_v1" else "public_qa_grounding"
    path = Path(__file__).with_name(name + ".py")
    if not path.is_file():
        path = Path(__file__).with_name(name.replace("_", "-") + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def verify_finite_adapter(model, torch_module=None):
    if torch_module is None:
        import torch as torch_module
    tensors = [(name, parameter) for name, parameter in model.named_parameters() if parameter.requires_grad]
    if not tensors or any("lora_" not in name for name, _ in tensors):
        raise RuntimeError("grounding_trainable_adapter_inventory_invalid")
    if any(not bool(torch_module.isfinite(parameter.detach()).all().item()) for _, parameter in tensors):
        raise RuntimeError("grounding_nonfinite_adapter_cannot_be_sealed")
    return {"passed": True, "tensorCount": len(tensors), "nonFiniteTensorCount": 0, "dtypes": sorted({str(parameter.dtype) for _, parameter in tensors}), "beforeCandidateSealing": True}


def sha(path):
    return sha256_file(path)


def admission(data_path, manifest_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("datasetSha256") != sha(data_path) or manifest.get("upstreamRevision") != REVISION or manifest.get("license") != "CC-BY-SA-4.0" or manifest.get("heldoutUsed") is not False:
        raise ValueError("public_dataset_binding_invalid")
    rows = [json.loads(line) for line in Path(data_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    families, ids = {}, set()
    for row in rows:
        if row["id"] in ids or row.get("split") not in ("train", "validation") or row.get("upstreamSplit") != "train" or row.get("upstreamRevision") != REVISION:
            raise ValueError("public_split_invalid")
        ids.add(row["id"])
        if row["familyId"] in families and families[row["familyId"]] != row["split"]:
            raise ValueError("public_family_leakage")
        families[row["familyId"]] = row["split"]
        if row.get("upstreamAnnotation", {}).get("kind") != "human_authored_question_answer_spans" or row.get("sourceLicense") != "CC-BY-SA-4.0" or row.get("localHumanReviewPerformed") is not False:
            raise ValueError("public_annotation_provenance_invalid")
        if row["question"] != row["originalQa"]["question"] or row["answers"] != row["originalQa"]["answers"] or row["isImpossible"] != row["originalQa"]["is_impossible"] or hashlib.sha256(row["context"].encode()).hexdigest() != row["contextSha256"]:
            raise ValueError("original_annotation_changed")
        if row["isImpossible"]:
            if row["answers"]:
                raise ValueError("unanswerable_annotation_invalid")
        elif not row["answers"] or any(not a["text"] or row["context"][a["answer_start"]:a["answer_start"] + len(a["text"])] != a["text"] for a in row["answers"]):
            raise ValueError("answer_span_invalid")
        if re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b01[016789][- .]?\d{3,4}[- .]?\d{4}\b|\b\d{6}[- ]?[1-8]\d{6}\b", row["question"] + "\n" + row["context"], re.I):
            raise ValueError("privacy_pattern_detected")
    counts = {split: sum(r["split"] == split for r in rows) for split in ("train", "validation")}
    if counts != manifest["counts"] or counts["train"] < 320 or counts["validation"] < 64 or [r["id"] for r in rows] != manifest["rowIds"]:
        raise ValueError("public_dataset_counts_invalid")
    return rows, manifest


def target(row):
    answer = "" if row["isImpossible"] else row["answers"][0]["text"]
    return {"answer": answer, "evidenceQuote": answer, "abstained": row["isImpossible"]}


def encode_row(tokenizer, row, sequence_length=1024, full_context=False):
    context = row["context"]
    answer = None if row["isImpossible"] else row["answers"][0]
    anchor_start = 0 if answer is None else answer["answer_start"]
    anchor_end = 0 if answer is None else anchor_start + len(answer["text"])
    radius = len(context)
    while True:
        start, end = max(0, anchor_start - radius), min(len(context), anchor_end + radius)
        selected = context[start:end]
        messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": json.dumps({"question": row["question"], "document": selected}, ensure_ascii=False)}]
        prefix = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        # The selected Reasoning model opens a reasoning block. Do not invent a
        # chain of thought for a human-authored extractive answer.
        completion = ("\n</think>\n" if prefix.rstrip().endswith("<think>") else "") + json.dumps(target(row), ensure_ascii=False, separators=(",", ":"))
        prefix_ids = tokenizer.encode(prefix, add_special_tokens=False)
        answer_ids = tokenizer.encode(completion, add_special_tokens=False) + [tokenizer.eos_token_id]
        full = prefix_ids + answer_ids
        if len(full) <= sequence_length:
            if answer is not None and context[anchor_start:anchor_end] != answer["text"]:
                raise ValueError("answer_span_changed")
            if answer is not None and selected[anchor_start-start:anchor_end-start] != answer["text"]:
                raise ValueError("answer_removed_from_window")
            return {"input_ids": full, "attention_mask": [1] * len(full), "labels": [-100] * len(prefix_ids) + answer_ids}, {"id": row["id"], "contextStart": start, "contextEnd": end, "tokens": len(full), "answerPreserved": True, "originalContextSha256": row["contextSha256"], "selectedContextSha256": hashlib.sha256(selected.encode()).hexdigest()}
        if full_context:
            raise ValueError("grounding_full_context_exceeds_token_budget")
        if radius == 0:
            raise ValueError("answer_and_question_exceed_token_budget")
        radius //= 2


def pad_batch(features, pad_token_id):
    """Right-pad only to this batch's longest sequence; never mask real EOS labels."""
    if not features or any(not 0 < len(row["input_ids"]) <= 1024 or len(row["attention_mask"]) != len(row["input_ids"]) or len(row["labels"]) != len(row["input_ids"]) for row in features):
        raise ValueError("training_batch_sequence_invalid")
    length = max(len(row["input_ids"]) for row in features)
    return [{"input_ids": row["input_ids"] + [pad_token_id] * (length - len(row["input_ids"])),
             "attention_mask": row["attention_mask"] + [0] * (length - len(row["input_ids"])),
             "labels": row["labels"] + [-100] * (length - len(row["input_ids"]))}
            for row in features]


def supervised_causal_positions(row, eos_token_id):
    """Return logit positions predicting the contiguous supervised completion."""
    if set(row) != {"input_ids", "attention_mask", "labels"}:
        raise ValueError("selective_loss_batch_invalid")
    input_ids, attention_mask, labels = (row[name] for name in ("input_ids", "attention_mask", "labels"))
    if not input_ids or len(attention_mask) != len(input_ids) or len(labels) != len(input_ids) or any(mask != 1 for mask in attention_mask):
        raise ValueError("selective_loss_batch_invalid")
    supervised = [index for index, label in enumerate(labels) if label != -100]
    if (not supervised or supervised[0] == 0 or supervised != list(range(supervised[0], len(labels)))
            or any(labels[index] != input_ids[index] for index in supervised)
            or labels[-1] != eos_token_id):
        raise ValueError("selective_loss_mask_invalid")
    # Causal LM logit at p - 1 predicts the supervised label at p.
    return [position - 1 for position in supervised]


def collate_rows(features, pad_token_id):
    from transformers import default_data_collator
    if len(features) != 1:
        raise ValueError("training_batch_size_one_required")
    padded = pad_batch(features, pad_token_id)
    logits_to_keep = supervised_causal_positions(padded[0], pad_token_id)
    batch = default_data_collator(padded)
    label_positions = batch["labels"].new_tensor([position + 1 for position in logits_to_keep])
    batch["logits_to_keep"] = batch["labels"].new_tensor(logits_to_keep)
    batch["shift_labels"] = batch["labels"].index_select(1, label_positions).contiguous()
    return batch


def stage_for_max_steps(max_steps):
    if type(max_steps) is not int or max_steps not in (20, 40):
        raise ValueError("public_qa_stage_budget_invalid")
    return "public_qa_stage2" if max_steps == 40 else "public_qa_stage1"


def train(args, rows, manifest):
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise RuntimeError("isolated_training_job_required")
    from public_qa_memory_gate import wait_for_controller
    wait_for_controller()
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", WANDB_DISABLED="true", TOKENIZERS_PARALLELISM="false")
    helper_path = Path(__file__).with_name("train-foundation-lora.py")
    spec = importlib.util.spec_from_file_location("foundation_binding", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    root, lock = helper.verify_training_bindings(args)
    checked = set()
    for item in lock["files"]:
        file = (root / item["path"]).resolve()
        if not file.is_relative_to(root) or file.is_symlink() or sha(file) != item["sha256"]:
            raise RuntimeError("base_artifact_digest_mismatch")
        checked.add(item["path"])
    if not {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"} <= checked or not set(json.loads((root / "model.safetensors.index.json").read_text())["weight_map"].values()) <= checked:
        raise RuntimeError("base_weight_shard_unverified")
    identity = {"baseRepository": "fdtn-ai/Foundation-Sec-8B-Reasoning", "baseRevision": args.base_revision, "baseArtifactLockSha256": sha(root / "artifact-lock.json"), "datasetSha256": sha(args.data), "manifestSha256": sha(args.manifest), "trainerSha256": sha(__file__), "artifactHelperSha256": sha(Path(__file__).with_name("training_artifacts.py")), "bindingHelperSha256": sha(helper_path), "image": os.environ.get("EVIDSCOPE_TRAINING_IMAGE", ""), "rank": 8, "sequenceLength": 1024, "gpuMemoryFraction": args.gpu_memory_fraction, "batchSize": 1, "gradientAccumulationSteps": 16, "seed": 42, "learningRate": 0.0001, "maxSteps": args.max_steps, "stage": stage_for_max_steps(args.max_steps)}
    grounding_lineage = None
    continuation = manifest.get("stage") == "public_qa_grounding_continuation_v1"
    if getattr(args, "grounding_provenance", None):
        grounding = grounding_helper(manifest.get("stage"))
        if args.max_steps != 20 or args.resume_from_checkpoint or args.resume_provenance or not args.warmstart_adapter:
            raise RuntimeError("grounding_requires_adapter_only_new_twenty_steps")
        identity.update(stage=grounding.STAGE, groundingHelperSha256=sha(Path(grounding.__file__)), contextSelection="full_original_context", precision="bf16", modelDtype="bfloat16", quantComputeDtype="bfloat16")
        if continuation:
            identity.update(learningRate=grounding.LEARNING_RATE, sampler=dict(grounding.SAMPLER))
        grounding_lineage = grounding.verify_grounding_provenance(args.grounding_provenance, args.warmstart_adapter, identity, args.output)
        print(json.dumps({"groundingWarmstart": grounding_lineage}), flush=True)
    elif getattr(args, "warmstart_adapter", None):
        raise RuntimeError("warmstart_requires_grounding_provenance")
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", identity["image"]):
        raise RuntimeError("training_image_binding_required")
    output = Path(args.output).resolve()
    if not output.is_relative_to(Path("/checkpoints").resolve()):
        raise RuntimeError("training_output_path_invalid")
    completed_steps = 0
    resume_lineage = None
    if args.resume_provenance and not args.resume_from_checkpoint:
        raise RuntimeError("resume_provenance_requires_checkpoint")
    new_output = not args.resume_from_checkpoint
    if args.resume_from_checkpoint:
        resume = Path(args.resume_from_checkpoint).resolve()
        if args.resume_provenance:
            from public_qa_resume import verify_resume_provenance, validate_resume_paths
            resume_lineage = verify_resume_provenance(resume, identity, args.resume_provenance, os.environ.get("EVIDSCOPE_RESUME_PROVENANCE_SHA256"))
            validate_resume_paths(resume, output, resume_lineage)
            new_output = True
            completed_steps = resume_lineage["sourceGlobalStep"]
            print(json.dumps({"resumeLineage": resume_lineage}), flush=True)
        else:
            if not resume.is_relative_to(output):
                raise RuntimeError("checkpoint_path_invalid")
            completed_steps = verify_checkpoint(resume, identity)["globalStep"]
        if completed_steps >= args.max_steps:
            raise RuntimeError("checkpoint_already_reached_requested_steps")
    if identity["stage"] == "public_qa_stage2" and (not resume_lineage or resume_lineage.get("schemaVersion") != 2):
        raise RuntimeError("stage_two_requires_pinned_extension_lineage")
    if new_output:
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            output.mkdir(exist_ok=False)
        except FileExistsError as error:
            raise RuntimeError("training_output_must_be_new") from error
    from public_qa_cuda_runtime import prepare
    print(json.dumps({"cudaLinker": prepare()}), flush=True)
    from public_qa_thermal import read_gpu_temperature, wait_for_thermal_budget
    print(json.dumps({"directGpuTemperatureC": read_gpu_temperature()}), flush=True)
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, Trainer, TrainingArguments, TrainerCallback
    from peft import LoraConfig, get_peft_model, PeftModel
    from public_qa_kbit import prepare_memory_efficient_kbit
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
    tokenizer.pad_token = tokenizer.eos_token
    encoded = [encode_row(tokenizer, row, full_context=grounding_lineage is not None) for row in rows]
    if continuation:
        for features, record in encoded:
            record["inputSha256"] = grounding.canonical_hash(features)
    training_rows = [row for row in rows if row["split"] == "train"]
    training_encoded = [item[0] for row, item in zip(rows, encoded) if row["split"] == "train"]
    exposure = grounding.ExposureRecorder(training_rows, training_encoded, output / "training-exposure.json", identity["datasetSha256"]) if continuation else None
    if not args.resume_from_checkpoint or resume_lineage:
        atomic_json(output / "encoding-receipt.json", {"datasetSha256": sha(args.data), "rows": [item[1] for item in encoded]})
    if not torch.cuda.is_available():
        raise RuntimeError("training_gpu_unavailable")
    if grounding_lineage and not torch.cuda.is_bf16_supported():
        raise RuntimeError("grounding_bf16_gpu_support_required")
    model_dtype = torch.bfloat16 if grounding_lineage else torch.float16
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(args.gpu_memory_fraction, 0)
    torch.manual_seed(42)
    torch.cuda.reset_peak_memory_stats()
    model = AutoModelForCausalLM.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False, device_map={"": 0}, torch_dtype=model_dtype, attn_implementation="sdpa", quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=model_dtype))
    if grounding_lineage:
        from public_qa_grounding_kbit import prepare_grounding_bf16_kbit
        model = prepare_grounding_bf16_kbit(model)
    else:
        model = prepare_memory_efficient_kbit(model)
    torch.cuda.empty_cache()
    if grounding_lineage:
        model = PeftModel.from_pretrained(model, args.warmstart_adapter, is_trainable=True, local_files_only=True)
        configuration = model.peft_config["default"]
        if configuration.r != 8 or configuration.lora_alpha != 16 or set(configuration.target_modules) != {"q_proj", "k_proj", "v_proj", "o_proj"}:
            raise RuntimeError("grounding_adapter_configuration_incompatible")
        adapter_loaded = {"groundingAdapterLoaded": True, "sourceGlobalStep": grounding_lineage["sourceGlobalStep"], "newGlobalStep": 0, "optimizerStateLoaded": False, "schedulerStateLoaded": False}
        if continuation:
            adapter_loaded["sourceOptimizerHistoryUpdates"] = grounding.SOURCE_HISTORY
        print(json.dumps(adapter_loaded), flush=True)
    else:
        model = get_peft_model(model, LoraConfig(r=8, lora_alpha=16, lora_dropout=0.05, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"], bias="none", task_type="CAUSAL_LM"))
    model.config.use_cache = False
    stopped = {"requested": False, "optimizerUpdates": completed_steps, "skippedUpdates": 0}
    def stop(*_):
        stopped["requested"] = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    class ReceiptCallback(TrainerCallback):
        def on_train_begin(self, arguments, state, control, optimizer=None, lr_scheduler=None, **_):
            if grounding_lineage and (state.global_step != 0 or optimizer.state or lr_scheduler.state_dict().get("last_epoch") != 0):
                raise RuntimeError("grounding_optimizer_scheduler_not_reset")
            if completed_steps:
                updates = [int(value["step"].item()) if hasattr(value["step"], "item") else int(value["step"]) for value in optimizer.state.values() if "step" in value]
                scheduler_step = lr_scheduler.state_dict().get("last_epoch")
                if state.global_step != completed_steps or not updates or any(step != completed_steps for step in updates) or scheduler_step != completed_steps:
                    raise RuntimeError("resume_optimizer_scheduler_state_mismatch")
                print(json.dumps({"resumedGlobalStep": state.global_step, "optimizerStateCount": len(updates), "schedulerLastEpoch": scheduler_step}), flush=True)
            return control
        def on_step_end(self, arguments, state, control, lr_scheduler=None, **_):
            if state.global_step != stopped["optimizerUpdates"] + stopped["skippedUpdates"] + 1:
                raise RuntimeError("optimizer_step_sequence_mismatch")
            skipped = trainer.accelerator.optimizer_step_was_skipped
            stopped["skippedUpdates" if skipped else "optimizerUpdates"] += 1
            learning_rate = float(lr_scheduler.get_last_lr()[0]) if lr_scheduler and lr_scheduler.get_last_lr() else None
            if identity["stage"] == "public_qa_stage2" and completed_steps < state.global_step < args.max_steps and (learning_rate is None or not 0 < learning_rate <= identity["learningRate"]):
                raise RuntimeError("stage_two_learning_rate_not_active")
            print(json.dumps({"optimizerStep": state.global_step, "actualOptimizerUpdates": stopped["optimizerUpdates"], "skippedOptimizerUpdates": stopped["skippedUpdates"], "learningRate": learning_rate, "cudaPeakAllocatedBytes": torch.cuda.max_memory_allocated(), "cudaPeakReservedBytes": torch.cuda.max_memory_reserved()}), flush=True)
            if grounding_lineage and skipped:
                raise RuntimeError("grounding_optimizer_update_skipped")
            if continuation:
                if state.global_step < args.max_steps and (learning_rate is None or not 0 < learning_rate <= identity["learningRate"]):
                    raise RuntimeError("continuation_learning_rate_out_of_bounds")
                exposure.optimizer_completed(state.global_step)
                print(json.dumps({"continuationOptimizerGroup": exposure.document["groups"][-1], "processedMicrobatches": exposure.document["processedMicrobatches"], "totalAdapterHistoryOptimizerUpdates": grounding.SOURCE_HISTORY + state.global_step}), flush=True)
            if stopped["requested"]:
                control.should_save = True
                control.should_training_stop = True
            return control
        def on_save(self, arguments, state, control, **_):
            if continuation:
                exposure.snapshot(Path(arguments.output_dir) / f"checkpoint-{state.global_step}" / "training-exposure.json", state.global_step)
            seal_checkpoint(Path(arguments.output_dir) / f"checkpoint-{state.global_step}", identity, state.global_step)
            return control
    settings = TrainingArguments(output_dir=str(output), max_steps=args.max_steps, per_device_train_batch_size=1, per_device_eval_batch_size=1, gradient_accumulation_steps=16, gradient_checkpointing=True, learning_rate=identity["learningRate"], fp16=grounding_lineage is None, bf16=grounding_lineage is not None, report_to=[], save_strategy="steps", save_steps=10, eval_strategy="no", logging_steps=1, save_total_limit=2, seed=42, data_seed=42, dataloader_num_workers=0, dataloader_pin_memory=False)
    class ThermalTrainer(Trainer):
        def _get_train_sampler(self, *args, **kwargs):
            if not continuation:
                return super()._get_train_sampler(*args, **kwargs)
            class StratifiedSampler(torch.utils.data.Sampler):
                def __iter__(self):
                    return iter(exposure.order)
                def __len__(self):
                    return len(exposure.order)
                def set_epoch(self, epoch):
                    if epoch != 0:
                        raise RuntimeError("continuation_repeated_epoch_forbidden")
            return StratifiedSampler()
        def _load_rng_state(self, checkpoint):
            super()._load_rng_state(checkpoint)
            if completed_steps:
                print(json.dumps({"resumeRngStateLoaded": str(checkpoint)}), flush=True)
        def training_step(self, *args, **kwargs):
            wait_for_thermal_budget(torch)
            record = exposure.inspect(args[1] if len(args) > 1 else kwargs["inputs"]) if continuation else None
            result = super().training_step(*args, **kwargs)
            if continuation:
                exposure.completed(record)
                print(json.dumps({"continuationTrainingSample": record}), flush=True)
            return result
        def prediction_step(self, *args, **kwargs):
            if stopped["requested"]:
                raise SystemExit(75)
            wait_for_thermal_budget(torch)
            return super().prediction_step(*args, **kwargs)
    trainer = ThermalTrainer(model=model, args=settings, train_dataset=training_encoded, eval_dataset=[item[0] for row, item in zip(rows, encoded) if row["split"] == "validation"], data_collator=partial(collate_rows, pad_token_id=tokenizer.pad_token_id), callbacks=[ReceiptCallback()])
    # Compare the identical quantized base on the same untouched validation rows.
    # Loss is a training diagnostic, not a citation or Korean quality acceptance.
    with model.disable_adapter():
        baseline_metrics = trainer.evaluate(metric_key_prefix="base_eval")
    print(json.dumps({"baseValidationLoss": baseline_metrics["base_eval_loss"]}), flush=True)
    result = trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)
    if stopped["requested"]:
        raise SystemExit(75)
    if trainer.state.global_step != args.max_steps:
        raise RuntimeError("requested_optimizer_steps_not_completed")
    if stopped["skippedUpdates"] or stopped["optimizerUpdates"] != args.max_steps:
        raise RuntimeError("optimizer_updates_not_completed")
    metrics = {**baseline_metrics, **result.metrics, **trainer.evaluate()}
    adapter_finite_check = verify_finite_adapter(model) if grounding_lineage else None
    if adapter_finite_check:
        print(json.dumps({"adapterFiniteCheck": adapter_finite_check}), flush=True)
    candidate = output / "candidate"
    model.save_pretrained(candidate, safe_serialization=True)
    tokenizer.save_pretrained(candidate)
    receipt = {"schemaVersion": 2, "status": f"trained_{identity['stage']}", "identity": identity, "globalStep": trainer.state.global_step, "trainingMetrics": metrics, "trainingRunCompleted": True, "qualityClaimAllowed": False, "promotionAllowed": False, "heldOutTestUsedForTraining": False, "localHumanReviewPerformed": False, "upstreamAnnotation": "KLUE human authored questions and answer spans", "sourceLicense": manifest["license"], "attribution": manifest["attribution"], "targetFormat": "exact_human_answer_json_without_generated_reasoning", "cudaPeakAllocatedBytes": torch.cuda.max_memory_allocated(), "cudaPeakReservedBytes": torch.cuda.max_memory_reserved()}
    if resume_lineage:
        receipt["resumeLineage"] = resume_lineage
    if grounding_lineage:
        receipt["groundingLineage"] = {**grounding_lineage, "optimizerUpdatesThisExperiment": stopped["optimizerUpdates"]}
        receipt["adapterFiniteCheck"] = adapter_finite_check
    if continuation:
        receipt["trainingExposure"] = exposure.snapshot(candidate / "training-exposure.json", trainer.state.global_step)
        receipt["sourceOptimizerHistoryUpdates"] = grounding.SOURCE_HISTORY
        receipt["optimizerUpdatesThisExperiment"] = stopped["optimizerUpdates"]
        receipt["totalAdapterHistoryOptimizerUpdates"] = grounding.SOURCE_HISTORY + stopped["optimizerUpdates"]
    atomic_json(candidate / "training-receipt.json", receipt)
    seal_candidate(candidate, identity, trainer.state.global_step, metrics)
    print(json.dumps(receipt, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--token-check", action="store_true")
    parser.add_argument("--model-dir", default="/models/foundation-base")
    parser.add_argument("--base-revision", default="")
    parser.add_argument("--output", default="/checkpoints/runs/public-qa-stage1")
    parser.add_argument("--max-steps", type=int, choices=(20, 40), default=20)
    parser.add_argument("--gpu-memory-fraction", type=float, default=0.65)
    parser.add_argument("--resume-from-checkpoint")
    parser.add_argument("--resume-provenance")
    parser.add_argument("--grounding-provenance")
    parser.add_argument("--warmstart-adapter")
    args = parser.parse_args()
    if not 0.1 <= args.gpu_memory_fraction <= 0.65:
        raise ValueError("gpu_memory_fraction_invalid")
    rows, manifest = admission(args.data, args.manifest)
    grounding = manifest.get("stage") in ("public_qa_grounding_v1", "public_qa_grounding_continuation_v1")
    if grounding:
        grounding_helper(manifest.get("stage")).verify_grounding_data(rows, manifest, args.manifest)
        if not args.grounding_provenance or not args.warmstart_adapter or args.max_steps != 20 or args.resume_from_checkpoint or args.resume_provenance:
            raise ValueError("grounding_execution_arguments_required")
    elif args.grounding_provenance or args.warmstart_adapter:
        raise ValueError("grounding_dataset_required")
    print(json.dumps({"publicAnnotationAdmitted": True, "counts": manifest["counts"], "localHumanReviewPerformed": False, "qualityClaimAllowed": False}), flush=True)
    if args.token_check:
        os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
        tokenizer.pad_token = tokenizer.eos_token
        receipts = [encode_row(tokenizer, row, full_context=grounding)[1] for row in rows]
        print(json.dumps({"tokenCheckPassed": True, "count": len(receipts), "maxTokens": max(r["tokens"] for r in receipts), "allAnswersPreserved": all(r["answerPreserved"] for r in receipts)}), flush=True)
    elif not args.check_only:
        train(args, rows, manifest)


if __name__ == "__main__":
    main()
