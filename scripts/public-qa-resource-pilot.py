"""Explicit isolated preparation probes. Never returns a formal training receipt."""
import argparse
import json
import os
from pathlib import Path
import random
import socket
import time
from training_artifacts import atomic_json


def connect(host):
    try:
        with socket.create_connection((host, 8080), timeout=3):
            return True
    except OSError:
        return False


def select_pilot_features(encoded, count=32, seed=42):
    """Deterministic training sample that includes the longest admitted row."""
    if not isinstance(encoded, list) or not isinstance(count, int) or isinstance(count, bool) or count < 1 or len(encoded) < count:
        raise ValueError("pilot_feature_count_invalid")
    if any(not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], dict) or not isinstance(item[1], dict) or not 0 < len(item[0].get("input_ids", [])) <= 1024 or len(item[0].get("attention_mask", [])) != len(item[0]["input_ids"]) or len(item[0].get("labels", [])) != len(item[0]["input_ids"]) or item[1].get("tokens") != len(item[0]["input_ids"]) for item in encoded):
        raise ValueError("pilot_feature_invalid")
    longest = max(range(len(encoded)), key=lambda index: (len(encoded[index][0]["input_ids"]), -index))
    remaining = [index for index in range(len(encoded)) if index != longest]
    random.Random(seed).shuffle(remaining)
    return [encoded[index] for index in [longest, *remaining[:count - 1]]]


def run(args):
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise RuntimeError("isolated_preparation_required")
    from public_qa_memory_gate import wait_for_controller
    wait_for_controller()
    result = {"schemaVersion": 1, "mode": args.mode, "source": "isolated_preparation_probe", "podUid": Path("/etc/podinfo/uid").read_text().strip(), "formalTraining": False, "trainingRunAllowed": False}
    if args.mode == "probe":
        result["observations"] = {"deniedTargetConnected": connect(args.denied_host), "allowedControlConnected": connect(args.allowed_host), "serviceAccountTokenPresent": Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists(), "hostMountPresent": any(Path(p).exists() for p in ("/host", "/mnt/c/Users"))}
        result["limitations"] = ["A denied connection alone does not prove NetworkPolicy enforcement. Pair with a reachable control and external CNI counters.", "Absence of common host paths does not establish approvedVolumesOnly; inspect the live Pod spec externally.", "Controller must separately observe process exit, node GPU mapping, and complete isolation evidence."]
    else:
        # Resource-only pilot over already admitted public human-authored rows.
        # Learning rate is zero; no candidate save or human-review gate bypass.
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location("training", "/runtime/train-foundation-lora.py")
        training = module_from_spec(spec); spec.loader.exec_module(training)
        from types import SimpleNamespace
        binding = SimpleNamespace(model_dir="/models/foundation-base", data="/data/public-qa-stage1.jsonl", base_revision=os.environ.get("EVIDSCOPE_BASE_REVISION", ""))
        root, lock = training.verify_training_bindings(binding)
        for item in lock["files"]:
            file = (root / item["path"]).resolve()
            if not file.is_relative_to(root) or training.file_sha256(file) != item["sha256"]:
                raise RuntimeError("pilot_artifact_binding_mismatch")
        print("base_file_hashes_verified", flush=True)
        from public_qa_cuda_runtime import prepare
        print(json.dumps({"cudaLinker": prepare()}), flush=True)
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import LoraConfig, get_peft_model
        from public_qa_kbit import prepare_memory_efficient_kbit
        if not torch.cuda.is_available():
            raise RuntimeError("pilot_gpu_unavailable")
        torch.set_num_threads(2); torch.manual_seed(42)
        gpu_fraction = 0.65
        torch.cuda.set_per_process_memory_fraction(gpu_fraction, 0)
        trainer_spec = spec_from_file_location("public_qa_training", "/runtime/train-public-qa.py")
        public_qa = module_from_spec(trainer_spec); trainer_spec.loader.exec_module(public_qa)
        rows, manifest = public_qa.admission("/data/public-qa-stage1.jsonl", "/data/public-qa-stage1.manifest.json")
        tokenizer = AutoTokenizer.from_pretrained(str(root), local_files_only=True, trust_remote_code=False)
        tokenizer.pad_token = tokenizer.eos_token
        admitted = [(public_qa.encode_row(tokenizer, row), row) for row in rows if row["split"] == "train"]
        chosen = select_pilot_features([item[0] for item in admitted])
        model = AutoModelForCausalLM.from_pretrained(str(root), local_files_only=True, trust_remote_code=False, device_map={"": 0}, torch_dtype=torch.float16, attn_implementation="sdpa", quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16))
        model = get_peft_model(prepare_memory_efficient_kbit(model), LoraConfig(r=8, lora_alpha=16, lora_dropout=0.05, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"], bias="none", task_type="CAUSAL_LM"))
        model.config.use_cache=False
        model.train()
        torch.cuda.empty_cache()
        optimizer=torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],lr=0)
        original = {name: parameter.detach().cpu().clone() for name, parameter in model.named_parameters() if parameter.requires_grad}
        lengths = [len(feature["input_ids"]) for feature, _ in chosen]
        supervised_lengths = [sum(label != -100 for label in feature["labels"]) for feature, _ in chosen]
        torch.cuda.reset_peak_memory_stats()
        started=time.monotonic()
        for step in range(2):
            optimizer.zero_grad()
            for feature, _ in chosen[step * 16:(step + 1) * 16]:
                batch = {name: value.to("cuda") for name, value in public_qa.collate_rows([feature], tokenizer.pad_token_id).items()}
                with torch.autocast("cuda", dtype=torch.float16):
                    loss = model(**batch).loss / 16
                if not torch.isfinite(loss):
                    raise RuntimeError("pilot_loss_not_finite")
                loss.backward()
            optimizer.step()
        torch.cuda.synchronize()
        unchanged = all(torch.equal(original[name], parameter.detach().cpu()) for name, parameter in model.named_parameters() if parameter.requires_grad)
        if not unchanged:
            raise RuntimeError("zero_learning_rate_changed_parameters")
        actual_tokens = sum(lengths)
        supervised_tokens = sum(supervised_lengths)
        result["observations"]={"peakAllocatedBytes":torch.cuda.max_memory_allocated(), "peakReservedBytes":torch.cuda.max_memory_reserved(), "seconds":time.monotonic()-started, "device":torch.cuda.get_device_name(0), "maximumSequenceLength":1024, "observedMinimumTokens":min(lengths), "observedMeanTokens":sum(lengths)/len(lengths), "observedMaximumTokens":max(lengths), "actualTokens":actual_tokens, "fixedPaddingTokens":len(lengths)*1024, "tokenReductionFraction":1-actual_tokens/(len(lengths)*1024), "dynamicPadding":True, "selectiveCompletionLogits":True, "fullLogitTokens":actual_tokens, "supervisedLogitTokens":supervised_tokens, "logitTokenReductionFraction":1-supervised_tokens/actual_tokens, "batchSize":1, "backwardPasses":len(lengths), "optimizerSteps":2, "learningRate":0, "gpuMemoryFraction":gpu_fraction, "parametersUnchanged":unchanged, "datasetSha256":manifest["datasetSha256"], "localHumanReviewPerformed":False}
        result["limitations"]=["Public human-authored training rows are used only for a zero-learning-rate resource measurement; this is not formal training completion, task quality, or process-exit proof.", "Peak allocation includes the longest admitted row and cannot establish the memory of a later run with changed code, data, or hardware."]
    return result


if __name__ == "__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--mode",choices=("probe","resource-pilot"),required=True);parser.add_argument("--denied-host");parser.add_argument("--allowed-host")
    try:
        result=run(parser.parse_args());atomic_json("/tmp/preparation-result.json",result);print(json.dumps(result))
    except Exception:
        import traceback
        traceback.print_exc()
        raise SystemExit("preparation_probe_failed")
