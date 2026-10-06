"""Explicit isolated preparation probes. Never returns a formal training receipt."""
import argparse
import json
import os
from pathlib import Path
import socket
import time
from training_artifacts import atomic_json


def connect(host):
    try:
        with socket.create_connection((host, 8080), timeout=3):
            return True
    except OSError:
        return False


def run(args):
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise RuntimeError("isolated_preparation_required")
    result = {"schemaVersion": 1, "mode": args.mode, "source": "isolated_preparation_probe", "podUid": Path("/etc/podinfo/uid").read_text().strip(), "formalTraining": False, "trainingRunAllowed": False}
    if args.mode == "probe":
        result["observations"] = {"deniedTargetConnected": connect(args.denied_host), "allowedControlConnected": connect(args.allowed_host), "serviceAccountTokenPresent": Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists(), "hostMountPresent": any(Path(p).exists() for p in ("/host", "/mnt/c/Users"))}
        result["limitations"] = ["A denied connection alone does not prove NetworkPolicy enforcement. Pair with a reachable control and external CNI counters.", "Absence of common host paths does not establish approvedVolumesOnly; inspect the live Pod spec externally.", "Controller must separately observe process exit, node GPU mapping, and complete isolation evidence."]
    else:
        # Resource-only synthetic-token pilot. Learning rate is zero; no
        # task examples, candidate save, or human-review gate bypass.
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location("training", Path(__file__).with_name("train-foundation-lora.py"))
        training = module_from_spec(spec); spec.loader.exec_module(training)
        from types import SimpleNamespace
        binding = SimpleNamespace(model_dir="/models/foundation-base", data="/dataset/reviewed.jsonl", base_revision=os.environ.get("EVIDSCOPE_BASE_REVISION", ""))
        root, lock = training.verify_training_bindings(binding)
        for item in lock["files"]:
            file = (root / item["path"]).resolve()
            if not file.is_relative_to(root) or training.file_sha256(file) != item["sha256"]:
                raise RuntimeError("pilot_artifact_binding_mismatch")
        # Keep Torch/CUDA allocations out of the full base-file integrity pass.
        import torch
        from transformers import AutoModelForCausalLM, BitsAndBytesConfig
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        if not torch.cuda.is_available():
            raise RuntimeError("pilot_gpu_unavailable")
        torch.set_num_threads(2); torch.manual_seed(42)
        torch.cuda.set_per_process_memory_fraction(0.65, 0)
        model = AutoModelForCausalLM.from_pretrained(str(root), local_files_only=True, trust_remote_code=False, device_map={"": 0}, quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16))
        model = get_peft_model(prepare_model_for_kbit_training(model, use_gradient_checkpointing=True), LoraConfig(r=8, lora_alpha=16, lora_dropout=0.05, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"], bias="none", task_type="CAUSAL_LM"))
        model.config.use_cache=False
        optimizer=torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],lr=0)
        tokens = torch.full((1, 1024), 1, dtype=torch.long, device="cuda")
        started=time.monotonic()
        for _ in range(2):
            optimizer.zero_grad()
            for _ in range(16):
                (model(input_ids=tokens, labels=tokens).loss/16).backward()
            optimizer.step()
        torch.cuda.synchronize()
        result["observations"]={"peakAllocatedBytes":torch.cuda.max_memory_allocated(), "peakReservedBytes":torch.cuda.max_memory_reserved(), "seconds":time.monotonic()-started, "device":torch.cuda.get_device_name(0), "sequenceLength":1024, "batchSize":1, "backwardPasses":32, "optimizerSteps":2, "learningRate":0}
        result["limitations"]=["Synthetic resource pilot is not formal training completion, task quality, or process-exit proof."]
    return result


if __name__ == "__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--mode",choices=("probe","resource-pilot"),required=True);parser.add_argument("--denied-host");parser.add_argument("--allowed-host")
    try:
        result=run(parser.parse_args());atomic_json("/tmp/preparation-result.json",result);print(json.dumps(result))
    except Exception:
        raise SystemExit("preparation_probe_failed")
