"""Verify approved local GGUF bytes before replacing this process with llama.cpp."""
import hashlib
import json
import os
from pathlib import Path
import sys

def main():
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1" or not Path("/etc/podinfo/uid").is_file():
        raise SystemExit("isolated_pod_required")
    root = Path("/models/foundation-sec")
    file = root / "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"
    lock = json.loads((root / "artifact-lock.json").read_text())
    expected = "5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed"
    if lock.get("revision") != "0b58da4736f799f3cb5bbaffb8a39025f1c4e5df" or lock.get("sha256") != expected:
        raise SystemExit("artifact_lock_invalid")
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise SystemExit("artifact_digest_mismatch")
    args = [*sys.argv[1:]]
    # Optional promoted governance-mapping adapter (docs/governance-model.md): loaded but not applied, so only requests
    # that ask for it ("lora": [{"id": 0, "scale": 1}]) use it. The digest comes from the signed promotion receipt.
    adapter_sha = os.environ.get("EVIDSCOPE_GOVERNANCE_ADAPTER_SHA256", "")
    if adapter_sha:
        adapter = root / "governance-mapping-lora.gguf"
        if len(adapter_sha) != 64 or any(c not in "0123456789abcdef" for c in adapter_sha) or adapter.is_symlink():
            raise SystemExit("adapter_binding_invalid")
        digest = hashlib.sha256()
        with adapter.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != adapter_sha:
            raise SystemExit("adapter_digest_mismatch")
        args += ["--lora", str(adapter), "--lora-init-without-apply"]
    os.execv("/app/llama-server", ["/app/llama-server", *args])

if __name__ == "__main__":
    main()
