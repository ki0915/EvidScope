"""Offline checkpoint/artifact integrity. No torch imports or network access."""
import hashlib
import json
import os
import math
import sys
import mmap
import errno
from pathlib import Path


def canonical_hash(value):
    """Shared JSON hash subset: JS-safe integers, no fractional numeric input.

    Integral JSON floats are normalized (1.0 -> 1, -0.0 -> 0). Reject the
    remaining numeric representations instead of claiming RFC8785 support.
    """
    def normalize(item):
        if isinstance(item, bool) or item is None or isinstance(item, str):
            return item
        if isinstance(item, (int, float)):
            if not math.isfinite(item) or int(item) != item or abs(item) > 9007199254740991:
                raise ValueError("canonical_numeric_format_unsupported")
            return int(item)
        if isinstance(item, list):
            return [normalize(entry) for entry in item]
        if isinstance(item, dict):
            return {key: normalize(entry) for key, entry in item.items()}
        raise ValueError("canonical_value_unsupported")
    return hashlib.sha256(json.dumps(normalize(value), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def sha256_file(path):
    # Overlay-backed model PVCs can retain clean cache despite fadvise. Aligned
    # direct reads keep multi-GB shard verification out of the guest page cache.
    # Unsupported filesystems fall back to the ordinary verified stream below.
    if sys.platform.startswith("linux") and hasattr(os, "O_DIRECT") and Path(path).stat().st_size >= 64 * 1024 * 1024:
        try:
            direct_hash = hashlib.sha256()
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECT)
            try:
                with mmap.mmap(-1, 1024 * 1024) as buffer:
                    while True:
                        count = os.readv(descriptor, [buffer])
                        if not count:
                            return direct_hash.hexdigest()
                        direct_hash.update(buffer[:count])
                        if count < len(buffer):
                            return direct_hash.hexdigest()
            finally:
                os.close(descriptor)
        except OSError as error:
            if error.errno not in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
                raise
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        # The dedicated offline base PVC can contain 16GB of weights. Release
        # already-read clean cache pages while hashing, instead of filling the
        # WSL guest cache before model loading. This is advisory, never evidence
        # that physical memory was reclaimed; the host guard still measures it.
        advise = sys.platform.startswith("linux") and hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED")
        offset = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
            if advise:
                try:
                    os.posix_fadvise(stream.fileno(), offset, len(block), os.POSIX_FADV_DONTNEED)
                except OSError:
                    # Filesystems may ignore or reject the hint. Hash integrity
                    # remains mandatory and independent of cache policy.
                    advise = False
            offset += len(block)
    return h.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def inventory(root, excluded=()):
    root = Path(root).resolve()
    result = []
    for file in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if file.is_symlink():
            raise ValueError("artifact_symlink_forbidden")
        if file.is_file() and file.name not in excluded:
            if file.name.endswith(".partial"):
                raise ValueError("artifact_partial_file")
            result.append({"path": file.relative_to(root).as_posix(), "bytes": file.stat().st_size, "sha256": sha256_file(file)})
    return result


def seal_checkpoint(path, identity, step):
    path = Path(path)
    required = {"adapter_config.json", "adapter_model.safetensors", "trainer_state.json", "optimizer.pt", "scheduler.pt", "rng_state.pth"}
    files = inventory(path, {"checkpoint-complete.json"})
    if not required <= {item["path"] for item in files} or step < 1:
        raise ValueError("checkpoint_files_incomplete")
    if json.loads((path / "trainer_state.json").read_text())["global_step"] != step:
        raise ValueError("checkpoint_step_mismatch")
    atomic_json(path / "checkpoint-complete.json", {"schemaVersion": 1, "identity": identity, "globalStep": step, "files": files})


def verify_checkpoint(path, identity):
    path = Path(path)
    marker = json.loads((path / "checkpoint-complete.json").read_text(encoding="utf-8"))
    if marker.get("schemaVersion") != 1 or marker.get("identity") != identity or not isinstance(marker.get("globalStep"), int) or marker["globalStep"] < 1:
        raise ValueError("checkpoint_identity_mismatch")
    if marker.get("files") != inventory(path, {"checkpoint-complete.json"}):
        raise ValueError("checkpoint_artifact_changed")
    if json.loads((path / "trainer_state.json").read_text())["global_step"] != marker["globalStep"]:
        raise ValueError("checkpoint_step_mismatch")
    return marker


def seal_candidate(path, identity, step, metrics):
    path = Path(path)
    files = inventory(path, {"candidate-complete.json"})
    if not {"adapter_config.json", "adapter_model.safetensors", "training-receipt.json"} <= {item["path"] for item in files} or step < 1:
        raise ValueError("candidate_files_incomplete")
    marker = {"schemaVersion": 1, "identity": identity, "globalStep": step, "metrics": metrics, "files": files}
    atomic_json(path / "candidate-complete.json", marker)
    return marker


def verify_candidate(path):
    path = Path(path)
    marker = json.loads((path / "candidate-complete.json").read_text(encoding="utf-8"))
    if marker.get("schemaVersion") != 1 or not isinstance(marker.get("globalStep"), int) or marker["globalStep"] < 1:
        raise ValueError("candidate_step_invalid")
    if marker.get("files") != inventory(path, {"candidate-complete.json"}):
        raise ValueError("candidate_artifact_changed")
    receipt = json.loads((path / "training-receipt.json").read_text(encoding="utf-8"))
    if receipt.get("identity") != marker.get("identity") or receipt.get("globalStep") != marker["globalStep"] or receipt.get("status") != "trained_candidate":
        raise ValueError("candidate_receipt_mismatch")
    return {"schemaVersion": 1, "verified": True, "artifactSha256": sha256_file(path / "candidate-complete.json"), "identity": marker["identity"], "globalStep": marker["globalStep"], "fileCount": len(marker["files"])}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--receipt", default="/tmp/artifact-verification.json")
    args = parser.parse_args()
    try:
        result = verify_candidate(args.directory)
        trainer = Path(__file__).with_name("train-foundation-lora.py")
        identity = result["identity"]
        if identity.get("trainerSha256") != sha256_file(trainer) or identity.get("artifactHelperSha256") != sha256_file(__file__) or identity.get("image") != os.environ.get("EVIDSCOPE_TRAINING_IMAGE"):
            raise ValueError("candidate_execution_identity_mismatch")
        atomic_json(args.receipt, result)
        print(json.dumps(result, separators=(",", ":")))
    except Exception:
        raise SystemExit("candidate_verification_failed")
