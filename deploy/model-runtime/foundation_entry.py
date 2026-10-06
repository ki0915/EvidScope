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
    os.execv("/app/llama-server", ["/app/llama-server", *sys.argv[1:]])

if __name__ == "__main__":
    main()
