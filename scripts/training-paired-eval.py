"""Offline same-base / same-base+PEFT comparison. No deployment or promotion."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import time
from training_artifacts import atomic_json, sha256_file, verify_candidate, canonical_hash


def heldout(records, role):
    rows = [r for r in records if r.get("split") == "test" and r.get("roleId") == role]
    if len(rows) < 100 or len({r.get("id") for r in rows}) != len(rows):
        raise ValueError("reviewed_heldout_set_required")
    fields = ("id", "roleId", "split", "familyId", "sourceId", "language", "prompt", "evidence", "truth", "approvedOutput")
    for row in rows:
        payload = {key: row.get(key) for key in fields}
        if row.get("synthetic") is not False or row.get("humanReviewed") is not True or row.get("sourceConsent") is not True or row.get("piiReviewed") is not True or row.get("reviewedPayloadHash") != canonical_hash(payload):
            raise ValueError("reviewed_nonsynthetic_heldout_required")
    if not any(r.get("language") == "en" for r in rows):
        raise ValueError("english_comparison_required")
    return rows


def parse_output(raw):
    # Keep exact raw output separately; parser failure is an actual failed
    # response, never a generated stand-in or expectedOutput substitution.
    body = raw.split("</think>", 1)[-1].strip()
    try:
        result = json.loads(body)
        canonical_hash(result)
        return result if isinstance(result, dict) else {}
    except ValueError:
        return {}


def evaluate(args):
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise RuntimeError("isolated_evaluation_required")
    records = [json.loads(line) for line in Path(args.data).read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = heldout(records, args.role)
    candidate = verify_candidate(args.adapter_dir)
    identity = candidate["identity"]
    lock_path = Path(args.model_dir) / "artifact-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("repository") != "fdtn-ai/Foundation-Sec-8B-Reasoning" or lock.get("revision") != identity.get("baseRevision") or sha256_file(lock_path) != identity.get("baseArtifactLockSha256"):
        raise RuntimeError("paired_base_mismatch")
    for item in lock["files"]:
        root = Path(args.model_dir).resolve(); file = (root / item["path"]).resolve()
        if not file.is_relative_to(root) or sha256_file(file) != item["sha256"]:
            raise RuntimeError("paired_base_artifact_mismatch")
    image = os.environ.get("EVIDSCOPE_TRAINING_IMAGE", "")
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", image):
        raise RuntimeError("evaluation_image_required")
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", WANDB_DISABLED="true")
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel
    if not torch.cuda.is_available():
        raise RuntimeError("evaluation_gpu_unavailable")
    torch.set_num_threads(2);torch.cuda.set_per_process_memory_fraction(0.65, 0)
    properties=torch.cuda.get_device_properties(0)
    device_id=str(getattr(properties,"uuid", ""))
    if not device_id:
        raise RuntimeError("evaluation_device_identity_unavailable")
    tokenizer=AutoTokenizer.from_pretrained(args.model_dir,local_files_only=True,trust_remote_code=False)
    tokenizer.pad_token=tokenizer.eos_token
    base=AutoModelForCausalLM.from_pretrained(args.model_dir,local_files_only=True,trust_remote_code=False,device_map={"":0},quantization_config=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type="nf4",bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.float16))
    model=PeftModel.from_pretrained(base,args.adapter_dir,is_trainable=False,local_files_only=True);model.eval()
    resources={"cpuLimit":2,"memoryLimitMiB":12288,"gpuMemoryLimitMiB":int(properties.total_memory*0.65/1048576),"contextTokens":1024,"maxOutputTokens":512,"concurrency":1,"requestTimeoutMs":120000,"deviceId":device_id,"quantization":"NF4","runtimeImageSha256":image.rsplit(":",1)[1],"seed":42,"temperature":0}
    outputs={"baseline":{},"candidate":{}};raw_outputs={"baseline":{},"candidate":{}}
    for side in outputs:
        with (model.disable_adapter() if side=="baseline" else contextlib.nullcontext()):
            for row in rows:
                torch.manual_seed(42)
                messages=[{"role":"system","content":"Use only supplied evidence. Return JSON advisory only; preserve requested output language; never approve or certify legal compliance."},{"role":"user","content":json.dumps({"request":row["prompt"],"evidence":row["evidence"]},ensure_ascii=False)}]
                inputs=tokenizer.apply_chat_template(messages,tokenize=True,add_generation_prompt=True,return_tensors="pt").to("cuda")
                if inputs.shape[-1]+512>1024:
                    raise RuntimeError("evaluation_context_budget_exceeded")
                started=time.monotonic()
                with torch.inference_mode():
                    generated=model.generate(inputs,max_new_tokens=512,max_time=120,do_sample=False,pad_token_id=tokenizer.eos_token_id)
                torch.cuda.synchronize();elapsed=time.monotonic()-started
                content=tokenizer.decode(generated[0,inputs.shape[-1]:],skip_special_tokens=True)
                outputs[side][row["id"]]=parse_output(content)
                raw_outputs[side][row["id"]]={"content":content,"seconds":elapsed,"inputTokens":inputs.shape[-1],"outputTokens":generated.shape[-1]-inputs.shape[-1],"timedOut":elapsed>=120}
                if elapsed>=120:outputs[side][row["id"]]={}
    ids=sorted(row["id"] for row in rows)
    receipt={"schemaVersion":1,"source":"isolated_inference","synthetic":False,"baseArtifactSha256":sha256_file(lock_path),"candidateArtifactSha256":candidate["artifactSha256"],"datasetSha256":canonical_hash(rows),"modelCalls":len(rows)*2}
    for side in outputs:receipt[side]={"outputsSha256":canonical_hash(outputs[side]),"exampleIds":ids,"resourceConfiguration":resources}
    directory=Path(args.output);directory.mkdir(parents=True,exist_ok=False)
    for side in outputs:atomic_json(directory/(side+".json"),outputs[side])
    atomic_json(directory/"raw-outputs.json",raw_outputs);atomic_json(directory/"measurement-receipt.json",receipt)
    return {"pairedResponses":len(rows)*2,"comparisonRequired":True,"promotionAllowed":False}


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--data",required=True);parser.add_argument("--model-dir",default="/models/foundation-base");parser.add_argument("--adapter-dir",required=True);parser.add_argument("--output",required=True);parser.add_argument("--role",default="evidence-organizer")
    try:print(json.dumps(evaluate(parser.parse_args())))
    except Exception:raise SystemExit("paired_evaluation_failed")
