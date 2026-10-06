"""Ephemeral local CipherGuard classifier; no request logging or remote code.

Architecture/output names verified against the publisher's V5 model card:
https://huggingface.co/smartm2m-bdg/CipherGuard-V5.0-XLM-RoBERTa
The official ONNX graph has independent safety_logits and category_logits heads.
"""
import hashlib
import json
import math
import multiprocessing as mp
import os
from pathlib import Path
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "smartm2m-bdg/CipherGuard-V5.0-XLM-RoBERTa"
SAFETY = ("safe", "unsafe", "controversial")
CATEGORIES = ("PII", "Financial Information", "Credential/Secret", "Location/Device Information", "Health/Biometric Information", "API Key/Access Token", "Account Information", "HR/Payroll Information", "Internal Document", "Legal Information", "Organization/Project Information", "Real Estate Information")
MAX_BYTES = 65536

def reply(status, reason, safety="unknown", categories=None, processed=0, total=0, score=None):
    value = {"model": MODEL, "status": status, "reason": reason, "safety": safety, "categories": categories or [], "processedChunks": processed, "totalChunks": total}
    if score is not None:
        value["maxScore"] = score
    return value

def chunks_for_fields(fields, tokenizer):
    # Each field gets its own boundaries. Special tokens count towards 512.
    capacity = 512 - tokenizer.num_special_tokens_to_add(pair=False)
    if capacity <= 32:
        raise ValueError("tokenizer_special_tokens_invalid")
    chunks = []
    for name in ("prompt", "response", "message", "text"):
        text = fields.get(name, "")
        if not text:
            continue
        ids = tokenizer.encode(text, add_special_tokens=False, truncation=False)
        if not ids:
            continue
        start = 0
        while start < len(ids):
            chunks.append(tokenizer.build_inputs_with_special_tokens(ids[start:start + capacity]))
            if start + capacity >= len(ids):
                break
            start += capacity - 32
    return chunks

def screen(request, tokenizer, classify, clock=time.monotonic):
    if not isinstance(request, dict) or set(request) - {"textFields", "maxTokens", "maxChunks", "overlapTokens", "timeoutMs"}:
        return reply("error", "invalid_response")
    fields = request.get("textFields")
    if not isinstance(fields, dict) or set(fields) - {"prompt", "response", "message", "text"} or any(not isinstance(v, str) for v in fields.values()):
        return reply("error", "invalid_response")
    if request.get("maxTokens", 512) != 512 or request.get("maxChunks", 8) != 8 or request.get("overlapTokens", 32) != 32:
        return reply("error", "invalid_response")
    timeout = request.get("timeoutMs", 10000)
    if type(timeout) not in (int, float) or not 0 < timeout <= 10000:
        return reply("error", "invalid_response")
    if sum(len(v.encode("utf-8")) for v in fields.values()) > MAX_BYTES:
        return reply("unobserved", "input_limit")
    deadline = clock() + timeout / 1000
    chunks = chunks_for_fields(fields, tokenizer)
    total, processed, worst, categories, score = len(chunks), 0, "safe", set(), 0.0
    if not total:
        return reply("unobserved", "no_text")
    rank = {"safe": 0, "controversial": 1, "unsafe": 2}
    for chunk in chunks[:8]:
        if clock() >= deadline:
            return reply("partial" if processed else "timeout", "deadline", worst if worst != "safe" else "unknown", sorted(categories), processed, total, score)
        if len(chunk) > 512:
            raise ValueError("tokenizer_budget_violation")
        safety, category, confidence = classify(chunk)
        if safety not in SAFETY or (safety != "safe" and category not in CATEGORIES) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("classifier_contract_invalid")
        processed += 1
        if rank[safety] > rank[worst]:
            worst = safety
        if safety != "safe":
            categories.add(category)
        score = max(score, confidence)
        if clock() >= deadline:
            return reply("partial", "deadline", worst if worst != "safe" else "unknown", sorted(categories), processed, total, score)
    partial = processed < total
    return reply("partial" if partial else "complete", "chunk_limit" if partial else "completed", worst if not partial or worst != "safe" else "unknown", sorted(categories), processed, total, score)

def verify_local_manifest(root):
    manifest = json.loads((root / "artifact-lock.json").read_text())
    if manifest.get("modelId") != "cipherguard" or not re.fullmatch(r"[a-f0-9]{40}", manifest.get("revision", "")) or not manifest.get("files"):
        raise ValueError("artifact_lock_invalid")
    checked = set()
    for item in manifest["files"]:
        file = (root / item["path"]).resolve()
        if not file.is_relative_to(root.resolve()) or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")):
            raise ValueError("artifact_path_invalid")
        digest = hashlib.sha256()
        with file.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != item["sha256"]:
            raise ValueError("artifact_digest_mismatch")
        checked.add(item["path"])
    required = {"onnx/cipherguard_v5_int8.onnx", "tokenizer.json", "tokenizer_config.json", "config.json"}
    if not required <= checked:
        raise ValueError("artifact_files_missing")
    return manifest["revision"]

def worker(connection, model_dir):
    try:
        # Dependencies are imported only in the isolated worker, never in tests.
        import numpy as np
        import onnxruntime as ort
        from transformers import AutoTokenizer
        root = Path(model_dir)
        revision = verify_local_manifest(root)
        tokenizer = AutoTokenizer.from_pretrained(root, local_files_only=True, trust_remote_code=False)
        options = ort.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.log_severity_level = 4
        session = ort.InferenceSession(str(root / "onnx/cipherguard_v5_int8.onnx"), sess_options=options, providers=["CPUExecutionProvider"])
        if [v.name for v in session.get_outputs()] != ["safety_logits", "category_logits"]:
            raise ValueError("classifier_heads_invalid")
        def classify(ids):
            values = np.asarray([ids], dtype=np.int64)
            s, c = session.run(["safety_logits", "category_logits"], {"input_ids": values, "attention_mask": np.ones_like(values)})
            if s.shape != (1, 3) or c.shape != (1, 12):
                raise ValueError("classifier_shape_invalid")
            index = int(s[0].argmax())
            p = np.exp(s[0] - s[0].max())
            return SAFETY[index], CATEGORIES[int(c[0].argmax())] if index else None, float(p[index] / p.sum())
        connection.send({"ready": True})
        while True:
            req = connection.recv()
            try:
                result = screen(req, tokenizer, classify)
                result["modelRevision"] = revision
                connection.send(result)
            except Exception:
                connection.send(reply("error", "classifier_error"))
            finally:
                req = None
    except Exception:
        try:
            connection.send({"ready": False})
        except Exception:
            pass
    finally:
        connection.close()

class Engine:
    def __init__(self, model_dir):
        self.model_dir, self.lock, self.process, self.connection = model_dir, threading.Lock(), None, None
    def start(self):
        self.close()
        self.connection, child = mp.get_context("spawn").Pipe()
        self.process = mp.get_context("spawn").Process(target=worker, args=(child, self.model_dir), daemon=True)
        self.process.start()
        child.close()
        if not self.connection.poll(120) or self.connection.recv() != {"ready": True}:
            self.close()
            raise RuntimeError("classifier_unavailable")
    def close(self):
        if self.process:
            self.process.terminate()
            self.process.join(2)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(2)
        if self.connection:
            self.connection.close()
        self.process = self.connection = None
    def run(self, request):
        if not self.lock.acquire(blocking=False):
            return reply("unobserved", "body_unavailable")
        try:
            if not self.process or not self.process.is_alive():
                return reply("error", "classifier_error")
            self.connection.send(request)
            timeout = request.get("timeoutMs", 10000) if isinstance(request, dict) else 10000
            seconds = min(10.0, timeout / 1000) if type(timeout) in (int, float) and 0 < timeout <= 10000 else 10.0
            if not self.connection.poll(seconds):
                self.close()  # Native ONNX call cannot be interrupted in a thread.
                return reply("timeout", "deadline")
            return self.connection.recv()
        except Exception:
            self.close()
            return reply("error", "classifier_error")
        finally:
            self.lock.release()

def main():
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise SystemExit("isolated_pod_required")
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", TOKENIZERS_PARALLELISM="false")
    engine = Engine("/models/cipherguard")
    engine.start()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            okay = self.path == "/health" and engine.process and engine.process.is_alive()
            self.send_response(200 if okay else 503)
            self.end_headers()
        def do_POST(self):
            result = reply("error", "invalid_response")
            try:
                self.connection.settimeout(10)
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/screen" or not 0 < length <= MAX_BYTES or self.headers.get("Transfer-Encoding"):
                    raise ValueError("request_invalid")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("request_incomplete")
                request = json.loads(raw)
                raw = None
                result = engine.run(request)
                request = None
            except Exception:
                pass
            body = json.dumps(result, ensure_ascii=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    try:
        ThreadingHTTPServer(("127.0.0.1", 8091), Handler).serve_forever()
    finally:
        engine.close()

if __name__ == "__main__":
    main()
