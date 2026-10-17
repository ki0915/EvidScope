"""Run the session judge (a causal LM base, optionally with a trained LoRA adapter) over batch-runner request lines on a rented GPU.

Input: the request JSONL that scripts/session-inference.mjs `requests` / `external-requests` writes (id, messages, decoding). Output: the
same three files scripts/governance_mapping_batch.py writes, so `session-inference.mjs score-outputs` / `external-score` read them
unchanged: <prefix>.outputs.json {id: reply}, <prefix>.logprobs.json {id: [[token text, logprob in micro-nats], ...]} and
<prefix>.receipt.json. Decoding is greedy (the requests' temperature 0.1 / top_k 20 sampler is replaced by argmax so a run is repeatable
without a seeded server); the logprob of each emitted token is taken from the raw softmax, before any sampler, as llama-server reports
it. No grammar constrains the reply: a reply that is not the schema's JSON is scored as an abstention, and the schema-valid rate is
reported. Token texts are prefix differences of the decoded reply, so they join to exactly the reply text.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

LOGPROB_SCALE = 1000000


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_requests(path):
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [r.get("id") for r in rows]
    if len(set(ids)) != len(ids) or not all(isinstance(i, str) for i in ids):
        raise ValueError("request_ids_invalid")
    for r in rows:
        m = r.get("messages")
        if not isinstance(m, list) or [x.get("role") for x in m] != ["system", "user"]:
            raise ValueError("request_messages_invalid:" + r["id"])
    return rows


def token_pieces(tokenizer, ids):
    """Texts of the generated tokens whose concatenation is exactly decode(ids)."""
    pieces, previous = [], ""
    for n in range(1, len(ids) + 1):
        text = tokenizer.decode(ids[:n], skip_special_tokens=True)
        pieces.append(text[len(previous):] if text.startswith(previous) else text)
        previous = text
    return pieces


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--adapter")
    parser.add_argument("--requests", required=True)
    parser.add_argument("--prefix", required=True, help="output path prefix: <prefix>.outputs.json, .logprobs.json, .receipt.json")
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-new-tokens", type=int, default=256)
    args = parser.parse_args(argv)
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1", TOKENIZERS_PARALLELISM="false")
    for suffix in (".outputs.json", ".logprobs.json", ".receipt.json"):
        if Path(args.prefix + suffix).exists():
            raise SystemExit("output exists: " + args.prefix + suffix)
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    requests = read_requests(args.requests)
    started = time.monotonic()
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True)
    tokenizer.padding_side = "left"
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(args.model_dir, local_files_only=True, dtype=torch.bfloat16, device_map={"": 0},
                                                 attn_implementation="sdpa")
    if args.adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, args.adapter)
    model.eval()
    stop_ids = {tokenizer.eos_token_id}
    for name in ("<|im_end|>", "<|endoftext|>"):
        token_id = tokenizer.convert_tokens_to_ids(name)
        if isinstance(token_id, int) and token_id >= 0:
            stop_ids.add(token_id)
    prompts = {r["id"]: tokenizer.apply_chat_template(r["messages"], tokenize=False, add_generation_prompt=True) for r in requests}
    order = sorted(prompts, key=lambda i: len(prompts[i]))
    outputs, logprobs, truncated, splits = {}, {}, 0, 0

    def generate(batch):
        """(sequences, chosen) for one batch; a batch that runs out of GPU memory (long sessions) is split in halves, down to one request."""
        nonlocal splits
        try:
            encoded = tokenizer([prompts[i] for i in batch], return_tensors="pt", padding=True, add_special_tokens=False).to(0)
            with torch.no_grad():
                generated = model.generate(**encoded, do_sample=False, max_new_tokens=args.max_new_tokens, output_scores=False, output_logits=True,
                                           return_dict_in_generate=True, pad_token_id=tokenizer.pad_token_id, eos_token_id=sorted(stop_ids))
                sequences = generated.sequences[:, encoded["input_ids"].shape[1]:]
                # The chosen token's log-probability at each step, one step at a time (a stacked batch x steps x vocab tensor would not fit).
                chosen = torch.stack([torch.log_softmax(step.float(), dim=-1).gather(1, sequences[:, n:n + 1]).squeeze(1)
                                      for n, step in enumerate(generated.logits)], dim=1).tolist()
            return sequences.tolist(), chosen
        except torch.cuda.OutOfMemoryError:
            if len(batch) == 1:
                raise
        generated = encoded = None
        torch.cuda.empty_cache()
        splits += 1
        half = len(batch) // 2
        first, second = generate(batch[:half]), generate(batch[half:])
        return first[0] + second[0], first[1] + second[1]

    for start in range(0, len(order), args.batch_size):
        batch = order[start:start + args.batch_size]
        sequences, chosen = generate(batch)
        for row, request_id in enumerate(batch):
            ids, scores = [], []
            for position, token_id in enumerate(sequences[row]):
                if token_id in stop_ids:
                    break
                ids.append(token_id)
                scores.append(int(round(chosen[row][position] * LOGPROB_SCALE)))
            else:
                truncated += 1
            pieces = token_pieces(tokenizer, ids)
            outputs[request_id] = "".join(pieces)
            logprobs[request_id] = [[piece, score] for piece, score in zip(pieces, scores)]
        print(json.dumps({"done": min(start + args.batch_size, len(order)), "of": len(order)}), flush=True)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    outputs_text, logprobs_text = canonical(outputs), canonical(logprobs)
    Path(args.prefix + ".outputs.json").write_text(outputs_text + "\n", encoding="utf-8")
    Path(args.prefix + ".logprobs.json").write_text(logprobs_text + "\n", encoding="utf-8")
    adapter_file = Path(args.adapter) / "adapter_model.safetensors" if args.adapter else None
    receipt = {"runner": "session_judge_generate", "count": len(requests), "truncated": truncated, "oomSplits": splits, "decoding": "greedy",
               "requestsSha256": sha256_file(args.requests), "baseArtifactLockSha256": sha256_file(Path(args.model_dir) / "artifact-lock.json"),
               "adapterSha256": sha256_file(adapter_file) if adapter_file else None,
               "outputsSha256": hashlib.sha256(outputs_text.encode("utf-8")).hexdigest(),
               "logprobsSha256": hashlib.sha256(logprobs_text.encode("utf-8")).hexdigest(), "seconds": round(time.monotonic() - started, 1),
               "image": os.environ.get("EVIDSCOPE_TRAINING_IMAGE", "")}
    Path(args.prefix + ".receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
