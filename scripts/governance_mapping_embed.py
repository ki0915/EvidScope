"""Embeddings for governance-mapping retrieval, computed inside the offline llama.cpp container (docs/governance-model.md).

Starts the pinned llama-server with --embeddings on 127.0.0.1 inside the container, sends the texts written by
`node scripts/governance-mapping.mjs embed-texts` and writes one JSON file keyed by text digest (sha256 of the NFC text) that
src/governance-embeddings.mjs reads. Standard library only; nothing is downloaded. The file states which model produced the
vectors and over which texts; src/governance-mapping.mjs states how they are used.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request

SCHEMA_VERSION = 1


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def text_digest(text):
    return hashlib.sha256(unicodedata.normalize("NFC", text).encode("utf-8")).hexdigest()


def network_interfaces(root="/sys/class/net"):
    try:
        return sorted(os.listdir(root))
    except OSError:
        return []


def read_texts(path):
    """Each line is {"digest", "text"} as embed-texts writes it; the digest must be the text's own, so an edited line is refused."""
    lines = [line for line in Path(path).read_text(encoding="utf-8").split("\n") if line]
    items = []
    for line in lines:
        item = json.loads(line)
        if (not isinstance(item, dict) or set(item) != {"digest", "text"} or not isinstance(item["text"], str) or not item["text"]
                or item["digest"] != text_digest(item["text"])):
            raise ValueError("text_line_invalid")
        items.append(item)
    if not items or len({item["digest"] for item in items}) != len(items):
        raise ValueError("texts_invalid")
    return items, hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def http_json(url, payload=None, timeout=600):
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="GET" if payload is None else "POST", headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(64 * 1024 * 1024).decode("utf-8"))


def wait_ready(base, process, deadline):
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("llama_server_exited")
        try:
            if http_json(base + "/health", timeout=5).get("status") == "ok":
                return
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("llama_server_start_timeout")


def free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(args):
    texts, texts_hash = read_texts(args.texts)
    if Path(args.out).exists():
        raise FileExistsError(args.out)
    model_sha = sha256_file(args.model)
    if args.expected_model_sha256 and model_sha != args.expected_model_sha256:
        raise ValueError("model_digest_mismatch")
    interfaces = network_interfaces()
    port = args.port or free_loopback_port()
    # The batch and micro-batch equal the context so one text of up to --ctx tokens is embedded in one pass (llama-server requirement).
    command = [args.server_bin, "-m", args.model, "--host", "127.0.0.1", "--port", str(port), "--embeddings", "--pooling", args.pooling,
               "-c", str(args.ctx), "-b", str(args.ctx), "-ub", str(args.ctx), "-np", "1", "-ngl", str(args.gpu_layers), "--threads", str(args.threads)]
    started = datetime.now(timezone.utc).isoformat()
    vectors, dims, failures, reasons, props = {}, None, 0, {}, None
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        wait_ready(base, process, time.monotonic() + args.start_timeout)
        props = http_json(base + "/props", timeout=10)
        for start in range(0, len(texts), args.batch):
            chunk = texts[start:start + args.batch]
            asked = time.monotonic()
            try:
                response = http_json(base + "/v1/embeddings", {"input": [item["text"] for item in chunk], "encoding_format": "float"},
                                     timeout=args.request_timeout)
                data = sorted(response["data"], key=lambda entry: entry["index"])
                if len(data) != len(chunk):
                    raise ValueError("embedding_count_mismatch")
                for item, entry in zip(chunk, data):
                    vector = entry["embedding"]
                    if not isinstance(vector, list) or not vector or not all(isinstance(x, (int, float)) and x == x for x in vector):
                        raise ValueError("embedding_invalid")
                    if dims is None:
                        dims = len(vector)
                    if len(vector) != dims:
                        raise ValueError("embedding_dims_mismatch")
                    vectors[item["digest"]] = [round(float(x), 6) for x in vector]
            except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError) as error:
                failures += len(chunk)
                reason = str(error) if isinstance(error, ValueError) else type(error).__name__
                reasons[reason] = reasons.get(reason, 0) + 1
            # Rest the GPU between batches in proportion to the time the batch took (operator's choice, 2026-10-10).
            time.sleep((time.monotonic() - asked) * args.pause_ratio)
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    build = props.get("build_info") if isinstance(props, dict) else None
    out = {"schemaVersion": SCHEMA_VERSION, "source": "isolated_llama_cpp_embeddings", "operator": args.operator,
           "model": {"file": Path(args.model).name, "sha256": model_sha, "dims": dims or 0, "pooling": args.pooling},
           "server": {"binarySha256": sha256_file(args.server_bin), "buildInfo": build if isinstance(build, str) else None,
                      "contextTokens": args.ctx, "gpuLayers": args.gpu_layers},
           "isolation": {"networkInterfaces": interfaces, "verified": interfaces == ["lo"]},
           "textsSha256": texts_hash, "count": len(texts), "embedded": len(vectors), "failures": failures, "failureReasons": reasons,
           "pauseRatio": args.pause_ratio, "startedAt": started, "finishedAt": datetime.now(timezone.utc).isoformat(), "vectors": vectors}
    with open(args.out, "x", encoding="utf-8") as stream:
        stream.write(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--texts", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--server-bin", default="/app/llama-server")
    parser.add_argument("--model", required=True)
    parser.add_argument("--expected-model-sha256", default="")
    parser.add_argument("--pooling", default="cls", choices=("cls", "mean", "last"))
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ctx", type=int, default=2048)
    parser.add_argument("--batch", type=int, default=16)
    parser.add_argument("--gpu-layers", type=int, default=99)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--start-timeout", type=int, default=600)
    parser.add_argument("--request-timeout", type=int, default=300)
    parser.add_argument("--pause-ratio", type=float, default=0.5)
    args = parser.parse_args(argv)
    if not 0 <= args.pause_ratio <= 4 or args.batch < 1:
        parser.error("--pause-ratio must be between 0 and 4 and --batch at least 1")
    out = run(args)
    print(json.dumps({key: out[key] for key in ("count", "embedded", "failures", "failureReasons", "isolation")} | {"model": out["model"]}))
    return 0 if out["failures"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
