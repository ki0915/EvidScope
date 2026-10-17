"""QLoRA training of the governance-mapping adapter (docs/governance-model.md). No downloads, adapter only, no promotion.

Input rows come from `node scripts/governance-mapping.mjs training-set`: the exact prompt the runtime sends (system + user
messages with the retrieved catalog candidates) and the gold JSON as the target. The base is the safetensors release of the
runtime model, fdtn-ai/Foundation-Sec-1.1-8B-Instruct, so the adapter applies to the pinned Q4_K_M GGUF after conversion
with llama.cpp convert_lora_to_gguf.py. Merged weights are never written.
--check-only and --token-check run without GPU libraries; training needs the isolated container (EVIDSCOPE_ISOLATED=1), or, for the
session judge only, a rented GPU (--rented-gpu with EVIDSCOPE_RENTED_GPU=1, scripts/rented-gpu/): a machine that holds nothing but the
designed scenarios and public benchmark rows, so the PC's container isolation is not what protects anything there.
--shakedown trains the same recipe on the derived rows only (`training-set --shakedown`) to measure VRAM and time before the human
review is done. Its adapter goes to <output>/shakedown-adapter with status shakedown_not_promotable: verify_candidate refuses it,
it is never promoted and its numbers are not a quality result.
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
import time
from functools import partial

sys.path.insert(0, str(Path(__file__).resolve().parent))
from training_artifacts import atomic_json, seal_checkpoint, verify_checkpoint, seal_candidate, sha256_file

BASE_REPOSITORY = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
# Bases the session task may train on, for the side-by-side judge comparison (2026-10-17 model plan): the first base, kept so its
# recorded runs still verify, and the light general model that replaces it as the first judge candidate. Both use the Llama/Qwen
# projection names in RECIPE. The governance-mapping task stays on BASE_REPOSITORY, because its adapter must apply to the runtime GGUF.
SESSION_BASE_REPOSITORIES = (BASE_REPOSITORY, "Qwen/Qwen3-4B-Instruct-2507")
TASK = "governance-mapping"
RELATIONS = {"supports", "contradicts", "context_only"}
CONFIDENCE = {"low", "medium", "high"}
# r=8 on every linear projection; with completion-only logits this is sized for the 12 GB card under the 0.72 memory fraction
# (0.65 until 2026-10-13, when prompts with candidate descriptions ran out of memory; src/governance-training.mjs GPU_MEMORY_FRACTION).
RECIPE = {"rank": 8, "alpha": 16, "dropout": 0.05, "targetModules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
          "sequenceLength": 2048, "batchSize": 1, "gradientAccumulationSteps": 8, "epochs": 1, "learningRatePerMillion": 200, "warmupStepsPer1000": 30,
          "seed": 42, "saveSteps": 5}
# In-loop thermal pacing defaults (owner's rule, 2026-10-12: GPU at or below 75 C, slower runs accepted). See ThermalPacer.
# The pacer reads the card after a micro-batch's rest, when it has already dropped 4-6 C from its loaded value (RTX 3080 on the
# owner's PC: 74-75 C under load read as 69-72 C after the ~1 s rest). 70/65 therefore never fired while loaded peaks reached the
# guard's 75 C; 68/63 holds the rested reading near 63-68 C, so loaded peaks stay a few degrees under the guard.
THERMAL_PACING = {"triggerC": 68, "targetC": 63, "maxWaitSeconds": 300.0, "pollSeconds": 2.0}


def load_helper(name, file_name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file_name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ThermalPacer:
    """Rests a hot GPU between optimizer steps so the external 75 C guard rarely has to stop the container.

    Each external stop costs a new container and a ~3 minute base-model reload, so cooling in place is faster. Pacing is an
    optimisation only: the supervisor's 75 C stop (src/training-resource-guard.mjs) stays the hard safety limit. An unreadable
    sensor (one JSON warning) or a wait that reaches max_wait_seconds therefore never stops training here. Pacing only sleeps;
    it does not change what is learned.
    """

    def __init__(self, read_temperature, trigger_c, target_c, max_wait_seconds, should_stop=lambda: False, poll_seconds=THERMAL_PACING["pollSeconds"],
                 clock=time.monotonic, sleep=time.sleep, emit=lambda record: print(json.dumps(record), flush=True)):
        self.read_temperature, self.trigger_c, self.target_c, self.max_wait_seconds = read_temperature, trigger_c, target_c, max_wait_seconds
        self.should_stop, self.poll_seconds, self.clock, self.sleep, self.emit = should_stop, poll_seconds, clock, sleep, emit
        self.waits, self.wait_seconds, self.max_temperature_c, self.deadline_hits, self.read_failures = 0, 0.0, None, 0, 0

    def read(self):
        try:
            value = self.read_temperature()
        except Exception as error:  # NVML missing or failing: no pacing for this step; the external guard still applies.
            self.read_failures += 1
            if self.read_failures == 1:
                self.emit({"warning": "thermal_pacing_unavailable", "error": f"{type(error).__name__}: {error}"[:200]})
            return None
        if self.max_temperature_c is None or value > self.max_temperature_c:
            self.max_temperature_c = value
        return value

    def pace(self, step=None):
        """At or above trigger_c, sleep-poll until at or below target_c, a stop request, or max_wait_seconds; never raises."""
        if self.max_wait_seconds <= 0:
            return 0.0
        temperature = self.read()
        if temperature is None or temperature < self.trigger_c or self.should_stop():
            return 0.0
        started, first = self.clock(), temperature
        while temperature is not None and temperature > self.target_c and not self.should_stop():
            elapsed = self.clock() - started
            if elapsed >= self.max_wait_seconds:
                self.deadline_hits += 1
                break
            self.sleep(min(self.poll_seconds, self.max_wait_seconds - elapsed))
            temperature = self.read()
        waited = self.clock() - started
        self.waits += 1
        self.wait_seconds += waited
        self.emit({"thermalWait": {"optimizerStep": step, "fromC": first, "toC": temperature, "seconds": round(waited, 1),
                                   "reachedTarget": temperature is not None and temperature <= self.target_c}})
        return waited

    def summary(self):
        return {"triggerC": self.trigger_c, "targetC": self.target_c, "maxWaitSeconds": self.max_wait_seconds, "waits": self.waits,
                "waitSeconds": round(self.wait_seconds, 1), "maxTemperatureC": self.max_temperature_c, "deadlineHits": self.deadline_hits,
                "readFailures": self.read_failures}


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


# The session-inference task (improvement plan phase 2): same trainer, a different gold shape. Task version 2 targets the forced output
# schema {verdict, type, evidenceActionIds}; clean/abstain carry an empty list. Requirement ids are computed from the evidence by the node
# side (src/session-inference.mjs) and confidence is the verdict token's probability, so neither is a training target any more (version 1
# trained a constant 0.9/0.1 confidence and a table lookup). Only the structure, the verdict/type enums and the clean->empty rule are checked.
SESSION_VERDICTS = {"violation", "clean", "abstain"}
# The last four are the public agent-safety set's risk types (src/external-agent-sets.mjs, ASSEBench); same list as SESSION_TYPES in
# src/session-inference.mjs.
SESSION_TYPES = {"exfiltration", "defense_evasion", "audit_tampering", "destructive", "bulk_collection", "unauthorized_access", "prompt_injection", "fraud",
                 "other"}


def valid_session_target(text):
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return False
    if not isinstance(value, dict) or set(value) != {"verdict", "type", "evidenceActionIds"}:
        return False
    if value["verdict"] not in SESSION_VERDICTS or not isinstance(value["evidenceActionIds"], list) or len(value["evidenceActionIds"]) > 20:
        return False
    if not all(isinstance(x, str) for x in value["evidenceActionIds"]):
        return False
    violation = value["verdict"] == "violation"
    if value["type"] is None if violation else value["type"] is not None:
        return False
    if violation and value["type"] not in SESSION_TYPES:
        return False
    return violation or not value["evidenceActionIds"]


# task -> (roleId, target validator, taskVersion). Default keeps governance-mapping behaviour unchanged.
TASKS = {"governance-mapping": ("governance-assistant", valid_target, 1), "session-inference": ("session-auditor", valid_session_target, 2)}


def admission(path, shakedown=False, task="governance-mapping"):
    """Re-checks what the node admission already decided; the held-out test split never reaches this file."""
    role_id, valid, version = TASKS[task]
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    reasons, ids, families, digests = [], set(), {}, set()
    for row in rows:
        if row.get("task") != task or row.get("taskVersion") != version or row.get("roleId") != role_id:
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
        if not valid(row.get("target")):
            reasons.append("target_invalid")
        if row.get("labelSource") not in ("derived_mapping_table", "claude_drafted", "public_dataset") or (row.get("labelSource") == "claude_drafted" and not re.fullmatch(r"[a-f0-9]{64}", str(row.get("reviewedPayloadHash")))):
            reasons.append("label_provenance_invalid")
        # A public benchmark's own label (ASSEBench), for the session judge only: it labels whole sessions, so its rows carry no evidence.
        if row.get("labelSource") == "public_dataset" and (task != "session-inference" or row.get("reviewedPayloadHash") is not None
                                                           or not valid(row.get("target")) or json.loads(row["target"])["evidenceActionIds"]):
            reasons.append("public_dataset_row_invalid")
        if shakedown and (row.get("runMode") != "shakedown" or row.get("labelSource") != "derived_mapping_table"):
            reasons.append("shakedown_requires_derived_shakedown_rows")
        if not shakedown and row.get("runMode", "candidate") != "candidate":
            reasons.append("shakedown_rows_in_candidate_run")
    if any(len(splits) > 1 for splits in families.values()):
        reasons.append("family_split_leakage")
    if len(digests) != 1:
        reasons.append("catalog_digest_mixed")
    counts = {split: sum(row.get("split") == split for row in rows) for split in ("tune", "validation")}
    # A shakedown measures resources only, so the review minimums do not apply; it still needs both splits.
    if (counts["tune"] < 1 or counts["validation"] < 1) if shakedown else (counts["tune"] < 300 or counts["validation"] < 50):
        reasons.append("eligible_counts_below_policy")
    reasons = sorted(set(reasons))
    return rows, {"admitted": not reasons, "runMode": "shakedown" if shakedown else "candidate", "counts": counts, "reasons": reasons,
                  "qualityClaimAllowed": False, "promotable": not shakedown}


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


def base_repository_for(args):
    repository = getattr(args, "base_repository", BASE_REPOSITORY)
    allowed = SESSION_BASE_REPOSITORIES if getattr(args, "task", TASK) == "session-inference" else (BASE_REPOSITORY,)
    if repository not in allowed:
        raise RuntimeError("base_repository_not_allowed_for_task")
    return repository


def verify_bindings(args):
    """Binds the container inputs to the digests the controller inspected; every base file is re-hashed."""
    repository = base_repository_for(args)
    if not re.fullmatch(r"[a-f0-9]{40}", args.base_revision or ""):
        raise RuntimeError("base_revision_required")
    if os.environ.get("EVIDSCOPE_BASE_REPOSITORY") != repository or os.environ.get("EVIDSCOPE_BASE_REVISION") != args.base_revision:
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
    if lock.get("repository") != repository or lock.get("revision") != args.base_revision or not lock.get("files"):
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
    return {"task": getattr(args, "task", TASK), "baseRepository": base_repository_for(args), "baseRevision": args.base_revision, "baseArtifactLockSha256": sha256_file(root / "artifact-lock.json"),
            "datasetSha256": sha256_file(args.data), "trainerSha256": sha256_file(here), "artifactHelperSha256": sha256_file(here.with_name("training_artifacts.py")),
            "collateHelperSha256": sha256_file(here.with_name("train-public-qa.py")), "kbitHelperSha256": sha256_file(here.with_name("public-qa-kbit.py")),
            "thermalHelperSha256": sha256_file(here.with_name("public-qa-thermal.py")),
            "image": os.environ.get("EVIDSCOPE_TRAINING_IMAGE", ""), "gpuMemoryFractionPercent": round(args.gpu_memory_fraction * 100),
            "runMode": "shakedown" if args.shakedown else "candidate", "computeDtype": getattr(args, "compute_dtype", "float16"),
            "host": "rented_gpu" if getattr(args, "rented_gpu", False) else "isolated_container", **RECIPE}


def check_output(args):
    output = Path(args.output).resolve()
    if not output.is_relative_to(Path("/checkpoints").resolve()) or output == Path("/checkpoints").resolve():
        raise RuntimeError("training_output_path_invalid")
    if (output.name == "shakedown") != bool(args.shakedown):
        raise RuntimeError("training_output_run_mode_mismatch")
    if args.resume_from_checkpoint:
        resume = Path(args.resume_from_checkpoint).resolve()
        if not resume.is_relative_to(output) or not re.fullmatch(r"checkpoint-[1-9][0-9]*", resume.name):
            raise RuntimeError("checkpoint_path_invalid")
    elif output.exists() and any(output.iterdir()):
        raise RuntimeError("training_output_must_be_new")
    return output


def check_host(args, rows):
    """The PC trains only inside its isolated container. A rented GPU trains only the session judge (a shakedown first), on rows whose labels
    are designed (derived_mapping_table) or a public benchmark's own (public_dataset): no drafted or reviewed rows, nothing from the PC's
    collected records, which never become training rows."""
    if os.name != "posix":
        raise RuntimeError("isolated_training_job_required")
    if not getattr(args, "rented_gpu", False):
        if os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
            raise RuntimeError("isolated_training_job_required")
        return
    if os.environ.get("EVIDSCOPE_RENTED_GPU") != "1" or args.task != "session-inference":
        raise RuntimeError("rented_gpu_run_invalid")
    if any(row.get("labelSource") not in ("derived_mapping_table", "public_dataset") for row in rows):
        raise RuntimeError("rented_gpu_rows_invalid")


def train(args, rows):
    started = time.monotonic()
    check_host(args, rows)
    if not 0.1 <= args.gpu_memory_fraction <= 0.72:
        raise RuntimeError("gpu_memory_fraction_invalid")
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", WANDB_DISABLED="true", TOKENIZERS_PARALLELISM="false")
    root = verify_bindings(args)
    identity = identity_for(args, root)
    # A registry digest (repo@sha256:...) or the local image ID the Docker launcher verified with `docker inspect`; on a rented GPU the
    # digest of the installed package list (scripts/rented-gpu/setup.sh: pip-freeze@sha256:...).
    if not re.fullmatch(r"(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}", identity["image"]):
        raise RuntimeError("training_image_binding_required")
    output = check_output(args)
    if args.resume_from_checkpoint:
        verify_checkpoint(Path(args.resume_from_checkpoint).resolve(), identity)
    output.mkdir(parents=True, exist_ok=True)
    collate = load_helper("governance_collate", "train-public-qa.py")
    kbit = load_helper("governance_kbit", "public-qa-kbit.py")
    thermal = load_helper("governance_thermal", "public-qa-thermal.py")
    stop = {"requested": False}
    pacer = ThermalPacer(thermal.read_gpu_temperature, args.thermal_trigger_c, args.thermal_target_c, args.thermal_max_wait_seconds,
                         should_stop=lambda: stop["requested"])
    if args.thermal_max_wait_seconds > 0:
        print(json.dumps({"thermalPacing": {**pacer.summary(), "startTemperatureC": pacer.read()}}), flush=True)
    import torch
    # The pinned image has no C compiler, and triton compiles a small driver module on first GPU use, so importing
    # bitsandbytes' optional triton kernels fails. 4-bit QLoRA uses bitsandbytes' CUDA library, not those kernels, so report
    # triton unavailable before transformers or peft import bitsandbytes.
    import torch.utils._triton as torch_triton
    torch_triton.has_triton = lambda: False
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, Trainer, TrainingArguments, TrainerCallback
    from peft import LoraConfig, get_peft_model
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False)
    tokenizer.pad_token = tokenizer.eos_token
    half = torch.bfloat16 if args.compute_dtype == "bfloat16" else torch.float16
    # Reject an over-long row before the model takes VRAM.
    tune = [encode_row(tokenizer, row) for row in rows if row["split"] == "tune"]
    validation = [encode_row(tokenizer, row) for row in rows if row["split"] == "validation"]
    if not torch.cuda.is_available():
        raise RuntimeError("training_gpu_unavailable")
    torch.set_num_threads(2)
    torch.cuda.set_per_process_memory_fraction(args.gpu_memory_fraction, 0)
    torch.manual_seed(RECIPE["seed"])
    torch.cuda.reset_peak_memory_stats()
    # transformers 5 renamed torch_dtype to dtype (the PC image has 4.51.3, a rented GPU a 5.x release).
    import transformers
    dtype_key = "dtype" if int(transformers.__version__.split(".")[0]) >= 5 else "torch_dtype"
    model = AutoModelForCausalLM.from_pretrained(args.model_dir, local_files_only=True, trust_remote_code=False, device_map={"": 0}, **{dtype_key: half},
                                                 attn_implementation="sdpa", quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                 bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=half))
    model = kbit.prepare_memory_efficient_kbit(model)
    if half == torch.bfloat16:
        # public-qa-kbit.py stays byte-for-byte the pinned public QA runtime, which leaves the frozen non-normalization weights in float16;
        # a bf16 run (rented card) moves those back to bfloat16 so they match the compute dtype. Normalizations stay float32.
        for parameter in model.parameters():
            if parameter.dtype == torch.float16:
                parameter.data = parameter.data.to(dtype=torch.bfloat16)
    loaded = time.monotonic()
    torch.cuda.empty_cache()
    model = get_peft_model(model, LoraConfig(r=RECIPE["rank"], lora_alpha=RECIPE["alpha"], lora_dropout=RECIPE["dropout"], target_modules=RECIPE["targetModules"],
                                             bias="none", task_type="CAUSAL_LM"))
    model.config.use_cache = False
    signal.signal(signal.SIGTERM, lambda *_: stop.update(requested=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(requested=True))

    class Checkpoints(TrainerCallback):
        burst_started = None

        def on_step_begin(self, arguments, state, control, **_):
            self.burst_started = time.monotonic()
            return control

        def rest(self, step):
            # Rest the GPU after each micro-batch in proportion to its compute time (operator's choice, 2026-10-10: keep the card
            # cool rather than finish fastest), then, if it is still hot, cool in place rather than be stopped by the external 75 C
            # guard (ThermalPacer). Resting once per optimizer step let 8 micro-batches (~14 s at full power) heat the card from
            # ~62 C to 75 C and cool it again before the pacer read it (pilot 11, 2026-10-12: no wait, then a heat stop); per
            # micro-batch the same total rest keeps the card near its average and the pacer reads it every ~2 s. Neither changes
            # what is learned.
            if self.burst_started is not None and args.pause_ratio > 0:
                time.sleep((time.monotonic() - self.burst_started) * args.pause_ratio)
            pacer.pace(step)
            self.burst_started = time.monotonic()

        def on_substep_end(self, arguments, state, control, **_):
            self.rest(state.global_step)
            return control

        def on_step_end(self, arguments, state, control, **_):
            print(json.dumps({"optimizerStep": state.global_step, "cudaPeakAllocatedMiB": round(torch.cuda.max_memory_allocated() / 1048576)}), flush=True)
            self.rest(state.global_step)
            if stop["requested"]:
                control.should_save = True
                control.should_training_stop = True
            return control

        def on_save(self, arguments, state, control, **_):
            seal_checkpoint(Path(arguments.output_dir) / f"checkpoint-{state.global_step}", identity, state.global_step)
            return control

    # transformers 5 dropped warmup_ratio; its warmup_steps takes a fraction below 1 as the ratio instead.
    warmup_key = "warmup_steps" if int(transformers.__version__.split(".")[0]) >= 5 else "warmup_ratio"
    warmup = {warmup_key: RECIPE["warmupStepsPer1000"] / 1000}
    settings = TrainingArguments(output_dir=str(output), num_train_epochs=RECIPE["epochs"], per_device_train_batch_size=1, per_device_eval_batch_size=1,
                                 gradient_accumulation_steps=RECIPE["gradientAccumulationSteps"], gradient_checkpointing=True,
                                 learning_rate=RECIPE["learningRatePerMillion"] / 1e6, **warmup, lr_scheduler_type="cosine",
                                 fp16=half == torch.float16, bf16=half == torch.bfloat16, report_to=[], save_strategy="steps", save_steps=RECIPE["saveSteps"], save_total_limit=2, eval_strategy="epoch",
                                 logging_strategy="no", seed=RECIPE["seed"], data_seed=RECIPE["seed"], dataloader_num_workers=0, dataloader_pin_memory=False,
                                 remove_unused_columns=False)
    # The held-out test split is never loaded here; validation loss is a training diagnostic, not a quality measurement.
    trainer = Trainer(model=model, args=settings, train_dataset=tune, eval_dataset=validation,
                      data_collator=partial(collate.collate_rows, pad_token_id=tokenizer.eos_token_id,
                                                    max_length=RECIPE["sequenceLength"]), callbacks=[Checkpoints()])
    result = trainer.train(resume_from_checkpoint=args.resume_from_checkpoint or None)
    if stop["requested"]:
        # This container's pacing numbers, kept in its log: a resumed run's receipt covers only its last container.
        print(json.dumps({"thermalPacing": pacer.summary(), "stoppedAtStep": trainer.state.global_step}), flush=True)
        raise SystemExit(75)
    trained = time.monotonic()
    collate.verify_finite_adapter(model, torch)
    candidate = output / ("shakedown-adapter" if args.shakedown else "candidate")
    model.save_pretrained(candidate, safe_serialization=True)
    if any(path.name.startswith("model") and path.suffix == ".safetensors" for path in candidate.iterdir()):
        raise RuntimeError("merged_weights_forbidden")
    metrics = {**result.metrics, "cudaPeakAllocatedMiB": round(torch.cuda.max_memory_allocated() / 1048576)}
    timing = {"loadSeconds": round(loaded - started, 1), "trainSeconds": round(trained - loaded, 1), "totalSeconds": round(time.monotonic() - started, 1),
              "thermalPacing": pacer.summary()}
    receipt = {"schemaVersion": 2, "status": "shakedown_not_promotable" if args.shakedown else "trained_candidate", "identity": identity,
               "globalStep": trainer.state.global_step, "trainingMetrics": metrics, "timing": timing,
               "trainingRunCompleted": True, "heldOutTestUsedForTraining": False, "qualityClaimAllowed": False, "promotionAllowed": False,
               "next": "record the VRAM/time numbers (factsheet --kind training); do not convert, evaluate or promote a shakedown adapter" if args.shakedown
               else "convert with llama.cpp convert_lora_to_gguf.py, evaluate with scripts/governance_mapping_batch.py, gate with scripts/governance-mapping.mjs"}
    atomic_json(candidate / "training-receipt.json", receipt)
    seal_candidate(candidate, identity, trainer.state.global_step, metrics)
    print(json.dumps(receipt, ensure_ascii=False), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--task", default=TASK, choices=sorted(TASKS))
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--token-check", action="store_true")
    parser.add_argument("--model-dir", default="/models/base")
    parser.add_argument("--base-repository", default=BASE_REPOSITORY, choices=SESSION_BASE_REPOSITORIES)
    parser.add_argument("--base-revision", default="")
    parser.add_argument("--output", default="/checkpoints/governance-mapping/run")
    parser.add_argument("--gpu-memory-fraction", type=float, default=0.72)
    parser.add_argument("--resume-from-checkpoint")
    parser.add_argument("--shakedown", action="store_true")
    parser.add_argument("--pause-ratio", type=float, default=0.5)
    parser.add_argument("--thermal-trigger-c", type=int, default=THERMAL_PACING["triggerC"])
    parser.add_argument("--thermal-target-c", type=int, default=THERMAL_PACING["targetC"])
    parser.add_argument("--thermal-max-wait-seconds", type=float, default=THERMAL_PACING["maxWaitSeconds"])
    parser.add_argument("--compute-dtype", default="float16", choices=("float16", "bfloat16"))
    parser.add_argument("--rented-gpu", action="store_true")
    args = parser.parse_args(argv)
    if args.task != "session-inference" and args.base_repository != BASE_REPOSITORY:
        parser.error("--base-repository other than %s is only for --task session-inference" % BASE_REPOSITORY)
    if not 0 <= args.pause_ratio <= 4:
        parser.error("--pause-ratio must be between 0 and 4")
    # The trigger stays below the external guard's 75 C stop; target < trigger gives hysteresis.
    if not 40 <= args.thermal_target_c < args.thermal_trigger_c <= 74:
        parser.error("--thermal-target-c and --thermal-trigger-c must satisfy 40 <= target < trigger <= 74")
    # 0 turns pacing off (no sensor reads); the external guard is unchanged either way.
    if not 0 <= args.thermal_max_wait_seconds <= 1800:
        parser.error("--thermal-max-wait-seconds must be between 0 and 1800")
    rows, gate = admission(args.data, shakedown=args.shakedown, task=args.task)
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
