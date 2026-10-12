"""Batch inference for the governance mapping evaluation, run inside an offline container (docs/governance-model.md).

Starts the pinned llama.cpp server on 127.0.0.1 inside the container, sends the requests written by
`node scripts/governance-mapping.mjs requests`, and writes the outputs and a receipt that binds the model and
adapter digests, the exact request bytes, the decoding settings, the outputs and the network interfaces seen.
Standard library only; nothing is downloaded. The receipt states facts; the promotion gate decides what counts.
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
import urllib.error
import urllib.request

DECODING_KEYS = ("temperature", "top_p", "top_k", "seed", "max_tokens")
# Token log-probabilities are kept as integers in micro-nats: Python's repr and JavaScript's JSON.stringify disagree on floats, and the
# receipt and the report (src/governance-mapping-eval.mjs) hash the same canonical JSON.
LOGPROB_SCALE = 1000000
REQUEST_KEYS = {"id", "variant", "messages", "response_format", "adapter", *DECODING_KEYS}
# The product runtime's context (src/model-policy.mjs primary contextTokens, deploy/model-runtime/render.mjs --ctx-size).
RUNTIME_CONTEXT_TOKENS = 3072
BUDGET_EXCEEDED = "prompt_budget_exceeded"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value):
    """JSON text as src/crypto.mjs canonical() writes it for strings, booleans, null, integers and short decimals."""
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        text = repr(value)
        if "e" in text or "E" in text:
            raise ValueError("canonical_numeric_format_unsupported")
        return text
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + canonical(value[key]) for key in sorted(value)) + "}"
    raise ValueError("canonical_value_unsupported")


def network_interfaces(root="/sys/class/net"):
    try:
        return sorted(os.listdir(root))
    except OSError:
        return []


def read_requests(path):
    """Each line is canonical JSON of one request (scripts/governance-mapping.mjs); the list hash is taken over those exact bytes."""
    lines = [line for line in Path(path).read_text(encoding="utf-8").split("\n") if line]
    requests = []
    for line in lines:
        item = json.loads(line)
        if not isinstance(item, dict) or set(item) != REQUEST_KEYS or canonical(item) != line:
            raise ValueError("request_line_not_canonical")
        requests.append(item)
    if not requests or len({item["id"] for item in requests}) != len(requests) or len({item["variant"] for item in requests}) != 1:
        raise ValueError("requests_invalid")
    decoding = {key: requests[0][key] for key in DECODING_KEYS}
    if any({key: item[key] for key in DECODING_KEYS} != decoding for item in requests):
        raise ValueError("decoding_not_uniform")
    requests_hash = hashlib.sha256(("[" + ",".join(lines) + "]").encode("utf-8")).hexdigest()
    return requests, decoding, requests_hash


def token_logprobs(choice):
    """[[token text, logprob in micro-nats], ...] for the reply's tokens, as llama-server's OpenAI-style logprobs.content reports them.
    A reply without them when they were asked for is a failed measurement of that item, not an output without scores."""
    content = (choice.get("logprobs") or {}).get("content")
    if not isinstance(content, list):
        raise ValueError("logprobs_missing")
    out = []
    for entry in content:
        if not isinstance(entry, dict) or not isinstance(entry.get("token"), str) or isinstance(entry.get("logprob"), bool) \
                or not isinstance(entry.get("logprob"), (int, float)):
            raise ValueError("logprobs_invalid")
        out.append([entry["token"], int(round(float(entry["logprob"]) * LOGPROB_SCALE))])
    return out


def http_json(url, payload=None, timeout=600):
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="GET" if payload is None else "POST", headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(4 * 1024 * 1024).decode("utf-8"))


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
    requests, decoding, requests_hash = read_requests(args.requests)
    variant = requests[0]["variant"]
    if variant != args.variant:
        raise ValueError("variant_mismatch")
    wants_adapter = {item["adapter"] for item in requests}
    if wants_adapter != {bool(args.lora)}:
        raise ValueError("adapter_flag_mismatch")
    for path in (args.out, args.receipt, args.logprobs):
        if path and Path(path).exists():
            raise FileExistsError(path)
    model_sha = sha256_file(args.model)
    if args.expected_model_sha256 and model_sha != args.expected_model_sha256:
        raise ValueError("model_digest_mismatch")
    adapter_sha = sha256_file(args.lora) if args.lora else None
    interfaces = network_interfaces()
    port = args.port or free_loopback_port()
    command = [args.server_bin, "-m", args.model, "--host", "127.0.0.1", "--port", str(port), "-c", str(args.ctx), "-np", "1",
               "-ngl", str(args.gpu_layers), "--threads", str(args.threads)]
    if args.lora:
        command += ["--lora", args.lora, "--lora-init-without-apply"]
    started = datetime.now(timezone.utc).isoformat()
    outputs, failures, usage = {}, 0, {"promptTokens": 0, "completionTokens": 0, "maxPromptTokens": 0}
    reasons, truncated, logprobs = {}, 0, {}
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        wait_ready(base, process, time.monotonic() + args.start_timeout)
        props = http_json(base + "/props", timeout=10)
        for item in requests:
            body = {"messages": item["messages"], "response_format": item["response_format"], "stream": False, "cache_prompt": False, **decoding}
            if item["adapter"]:
                body["lora"] = [{"id": 0, "scale": 1.0}]
            if args.logprobs:
                # The chosen token's raw log-probability (softmax before the grammar and the sampler); the abstention calibration
                # (src/governance-abstention.mjs) scores each requirement id by the tokens that spell it.
                body["logprobs"] = True
                body["top_logprobs"] = 1
            asked = time.monotonic()
            try:
                response = http_json(base + "/v1/chat/completions", body, timeout=args.request_timeout)
                choice = response["choices"][0]
                content = choice["message"].get("content")
                if not isinstance(content, str) or choice.get("finish_reason") not in ("stop", "length"):
                    raise ValueError("finish_" + str(choice.get("finish_reason")))
                tokens = response.get("usage", {})
                prompt_tokens = int(tokens.get("prompt_tokens", 0))
                usage["maxPromptTokens"] = max(usage["maxPromptTokens"], prompt_tokens)
                # The product runtime (src/isolated-inference-client.mjs) refuses a prompt that leaves less than max_tokens of its
                # context for the reply. Measured with --ctx equal to the runtime context (the default), such an item fails here too
                # instead of being scored as an answer the product could never give.
                if prompt_tokens + decoding["max_tokens"] > args.ctx:
                    raise ValueError(BUDGET_EXCEEDED)
                # A reply cut at max_tokens is the model's answer for this item: it is kept as given and scored (it will not
                # parse), not dropped as an infrastructure failure.
                truncated += choice.get("finish_reason") == "length"
                if args.logprobs:
                    logprobs[item["id"]] = token_logprobs(choice)
                outputs[item["id"]] = content
                usage["promptTokens"] += prompt_tokens
                usage["completionTokens"] += int(tokens.get("completion_tokens", 0))
            except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError) as error:
                outputs[item["id"]] = ""
                failures += 1
                named = isinstance(error, ValueError) and (str(error).startswith("finish_") or str(error) == BUDGET_EXCEEDED)
                reason = str(error) if named else type(error).__name__
                reasons[reason] = reasons.get(reason, 0) + 1
            # Rest the GPU between requests in proportion to the time the request took (operator's choice, 2026-10-10).
            time.sleep((time.monotonic() - asked) * args.pause_ratio)
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    outputs_text = canonical(outputs)
    logprobs_text = canonical(logprobs) if args.logprobs else None
    build = props.get("build_info") if isinstance(props, dict) else None
    receipt = {"schemaVersion": 1, "source": "isolated_llama_cpp_batch", "variant": variant, "operator": args.operator,
               "modelFile": Path(args.model).name, "modelSha256": model_sha, "adapterFile": Path(args.lora).name if args.lora else None,
               "adapterSha256": adapter_sha, "server": {"binarySha256": sha256_file(args.server_bin), "buildInfo": build if isinstance(build, str) else None,
               "contextTokens": args.ctx, "gpuLayers": args.gpu_layers},
               "isolation": {"networkInterfaces": interfaces, "verified": interfaces == ["lo"]},
               "decoding": decoding, "requestsSha256": requests_hash, "outputsSha256": hashlib.sha256(outputs_text.encode("utf-8")).hexdigest(),
               "count": len(requests), "failures": failures, "failureReasons": reasons, "truncated": truncated, "pauseRatio": args.pause_ratio,
               "usage": usage, "startedAt": started, "finishedAt": datetime.now(timezone.utc).isoformat(),
               "logprobsSha256": hashlib.sha256(logprobs_text.encode("utf-8")).hexdigest() if args.logprobs else None,
               "logprobs": {"file": Path(args.logprobs).name, "topLogprobs": 1, "scale": LOGPROB_SCALE} if args.logprobs else None}
    with open(args.out, "x", encoding="utf-8") as stream:
        stream.write(outputs_text + "\n")
    if args.logprobs:
        with open(args.logprobs, "x", encoding="utf-8") as stream:
            stream.write(logprobs_text + "\n")
    with open(args.receipt, "x", encoding="utf-8") as stream:
        stream.write(json.dumps(receipt, ensure_ascii=False, indent=1) + "\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", required=True)
    parser.add_argument("--variant", required=True, choices=("zero_shot", "retrieval", "retrieval_constrained", "candidate"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--server-bin", default="/app/llama-server")
    parser.add_argument("--model", required=True)
    parser.add_argument("--expected-model-sha256", default="")
    parser.add_argument("--lora")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ctx", type=int, default=RUNTIME_CONTEXT_TOKENS)
    parser.add_argument("--gpu-layers", type=int, default=99)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--start-timeout", type=int, default=600)
    parser.add_argument("--request-timeout", type=int, default=120)
    parser.add_argument("--pause-ratio", type=float, default=0.5)
    parser.add_argument("--logprobs", default="", help="also write the reply tokens' log-probabilities to this file (abstention calibration)")
    args = parser.parse_args(argv)
    if not 0 <= args.pause_ratio <= 4:
        parser.error("--pause-ratio must be between 0 and 4")
    receipt = run(args)
    print(json.dumps({key: receipt[key] for key in ("variant", "count", "failures", "failureReasons", "truncated", "isolation", "modelSha256",
                                                     "adapterSha256")}))
    return 0 if receipt["failures"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
