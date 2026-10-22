"""Fetch a judge base onto a rented GPU at a pinned revision and verify every file (docs/rented-gpu.md).

Two modes, both writing <out>/artifact-lock.json in the format scripts/train-governance-mapping-lora.py verify_bindings reads:
  --expect-lock F   the PC already downloaded and locked this base (scripts/download-judge-base.mjs): fetch exactly the files the lock
                    names and require each sha256 to match, then copy the PC's lock byte for byte, so the training identity binds to
                    the same base the PC holds.
  --repository R --revision SHA [--subfolder D ...]
                    a base the PC has not downloaded (JEV-9B): list the files Hugging Face publishes at that revision, keep the
                    weights, tokenizer, config and the named subfolders, verify LFS files by sha256 and small files by their git blob
                    sha1, and write a new lock.
Only https://huggingface.co is contacted. Nothing is uploaded.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request

HUB = "https://huggingface.co"
ALLOWED = {"Qwen/Qwen3-4B-Instruct-2507", "autotrust/JEV-9B",
           # Popular local models for the zero-shot comparison on the PC (owner-approved 2026-10-18): ungated, Apache-2.0, native
           # transformers architectures (no remote code), small enough for a 12GB card in bf16.
           "openbmb/MiniCPM5-2B", "HuggingFaceTB/SmolLM3-3B", "ibm-granite/granite-4.1-3b"}
KEEP = {"config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "added_tokens.json",
        "vocab.json", "merges.txt", "chat_template.jinja", "model.safetensors.index.json", "LICENSE", "LICENSE.txt",
        # JEV-9B's System 1 block: the decision head, its slot layout and per-kind temperatures.
        "head.safetensors", "judge_config.json", "calibration.json",
        # its LoRA, fetched with --subfolder adapter.
        "adapter_config.json", "adapter_model.safetensors"}
SHARD = re.compile(r"model(-\d{5}-of-\d{5})?\.safetensors")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_oid(path):
    data = Path(path).read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"accept": "application/json"}), timeout=60) as response:
        return json.loads(response.read())


def download(url, target, size):
    """Streams to <target>.partial with resume, then renames. Retries a dropped connection a few times."""
    partial = Path(str(target) + ".partial")
    for attempt in range(5):
        have = partial.stat().st_size if partial.exists() else 0
        if have > size:
            raise RuntimeError("partial_larger_than_source:" + target.name)
        if have == size:
            break
        try:
            request = urllib.request.Request(url, headers={"Range": "bytes=%d-" % have} if have else {})
            with urllib.request.urlopen(request, timeout=120) as response, open(partial, "ab" if have else "wb") as stream:
                if have and response.status != 206:
                    raise RuntimeError("range_not_honoured")
                for chunk in iter(lambda: response.read(1 << 22), b""):
                    stream.write(chunk)
        except (OSError, RuntimeError) as error:
            if attempt == 4:
                raise
            print(json.dumps({"event": "retry", "file": target.name, "error": str(error)[:200]}), flush=True)
            time.sleep(2 ** attempt)
    partial.rename(target)


def listing(repository, revision, subfolders):
    """[{path, bytes, sha256|None, gitOid|None}] of the kept files at revision (top level plus the named subfolders)."""
    entries = get_json(f"{HUB}/api/models/{repository}/tree/{revision}")
    for folder in subfolders:
        entries += get_json(f"{HUB}/api/models/{repository}/tree/{revision}/{folder}")
    files = []
    for e in entries:
        if e.get("type") != "file":
            continue
        path = e["path"]
        folder, _, name = path.rpartition("/")
        if not (name in KEEP or SHARD.fullmatch(name)) or (folder and folder not in subfolders):
            continue
        lfs = e.get("lfs")
        files.append({"path": path, "bytes": lfs["size"] if lfs else e["size"], "sha256": lfs["oid"] if lfs else None, "gitOid": None if lfs else e["oid"]})
    names = {f["path"] for f in files}
    missing = {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"} - names
    if missing:
        raise RuntimeError("base_files_missing:" + ",".join(sorted(missing)))
    return sorted(files, key=lambda f: f["path"])


def fetch(repository, revision, out, files):
    out.mkdir(parents=True, exist_ok=True)
    verified = []
    for f in sorted(files, key=lambda x: x["bytes"]):
        target = out / f["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            print(json.dumps({"event": "downloading", "file": f["path"], "bytes": f["bytes"]}), flush=True)
            download(f"{HUB}/{repository}/resolve/{revision}/{f['path']}", target, f["bytes"])
        if target.stat().st_size != f["bytes"]:
            raise RuntimeError("size_mismatch:" + f["path"])
        sha256 = sha256_file(target)
        if (f["sha256"] and sha256 != f["sha256"]) or (f.get("gitOid") and git_blob_oid(target) != f["gitOid"]):
            raise RuntimeError("digest_mismatch:" + f["path"])
        verified.append({"path": f["path"], "sha256": sha256, "bytes": f["bytes"]})
    index = json.loads((out / "model.safetensors.index.json").read_text(encoding="utf-8"))
    if not set(index["weight_map"].values()) <= {f["path"] for f in verified}:
        raise RuntimeError("weight_shard_missing")
    return sorted(verified, key=lambda f: f["path"])


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--expect-lock")
    parser.add_argument("--repository")
    parser.add_argument("--revision")
    parser.add_argument("--subfolder", action="append", default=[])
    args = parser.parse_args(argv)
    out = Path(args.out).resolve()
    lock_path = out / "artifact-lock.json"
    if args.expect_lock:
        lock_bytes = Path(args.expect_lock).read_bytes()
        lock = json.loads(lock_bytes)
        repository, revision = lock["repository"], lock["revision"]
        files = [{"path": f["path"], "bytes": f["bytes"], "sha256": f["sha256"], "gitOid": None} for f in lock["files"]]
    else:
        repository, revision = args.repository, args.revision
        if not re.fullmatch(r"[a-f0-9]{40}", revision or ""):
            parser.error("--revision must be a 40-hex commit")
        files = listing(repository, revision, args.subfolder)
    if repository not in ALLOWED:
        parser.error("repository not allowed: %s" % repository)
    verified = fetch(repository, revision, out, files)
    if not args.expect_lock:
        lock_bytes = json.dumps({"repository": repository, "revision": revision, "files": verified}, separators=(",", ":")).encode("utf-8")
    if lock_path.exists() and lock_path.read_bytes() != lock_bytes:
        raise RuntimeError("existing_artifact_lock_mismatch")
    lock_path.write_bytes(lock_bytes)
    print(json.dumps({"event": "done", "repository": repository, "revision": revision, "files": len(verified),
                      "bytes": sum(f["bytes"] for f in verified), "artifactLockSha256": hashlib.sha256(lock_bytes).hexdigest()}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
