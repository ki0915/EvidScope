"""Expose the mounted real CUDA driver to Triton's C linker without root writes.

Call prepare() before importing torch/transformers/bitsandbytes. This only reads
ldconfig's cache and the driver file; it does not initialize CUDA or download code.
The pinned Triton implementation reads TRITON_LIBCUDA_PATH in libcuda_dirs().
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

_prepared = None
_TRUSTED_ROOTS = (Path("/usr/lib/wsl/drivers"), Path("/usr/lib/x86_64-linux-gnu"),
                  Path("/lib/x86_64-linux-gnu"), Path("/usr/lib64"))


def _resolve_driver(cache_text):
    candidates = set()
    for line in cache_text.splitlines():
        match = re.match(r"\s*libcuda\.so\.1\s+\([^)]*\)\s+=>\s+(/\S+)\s*$", line)
        if not match:
            continue
        candidate = Path(match.group(1)).resolve(strict=True)
        if not any(candidate.is_relative_to(root) for root in _TRUSTED_ROOTS):
            raise RuntimeError("cuda_driver_path_outside_system_libraries")
        if not candidate.is_file():
            raise RuntimeError("cuda_driver_not_regular_file")
        with candidate.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise RuntimeError("cuda_driver_not_elf")
        candidates.add(candidate)
    if len(candidates) != 1:
        raise RuntimeError("cuda_driver_missing_or_ambiguous")
    return next(iter(candidates))


def prepare():
    global _prepared
    if _prepared is not None:
        directory = Path(_prepared["linkDirectory"])
        if any((directory / name).resolve(strict=True) != Path(_prepared["driverPath"])
               for name in ("libcuda.so", "libcuda.so.1")):
            raise RuntimeError("cuda_link_directory_changed")
        os.environ["TRITON_LIBCUDA_PATH"] = str(directory)
        return dict(_prepared)

    cache = subprocess.run(["/sbin/ldconfig", "-p"], check=True, capture_output=True,
                           text=True, timeout=10).stdout
    driver = _resolve_driver(cache)
    digest = hashlib.sha256()
    with driver.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    # mkdtemp creates a private 0700 directory, avoiding an existing shared path.
    directory = Path(tempfile.mkdtemp(prefix="evidscope-cuda-link-", dir="/tmp"))
    for name in ("libcuda.so.1", "libcuda.so"):
        (directory / name).symlink_to(driver)
    os.environ["TRITON_LIBCUDA_PATH"] = str(directory)
    _prepared = {"driverPath": str(driver), "driverSha256": digest.hexdigest(),
                 "linkDirectory": str(directory), "environment": "TRITON_LIBCUDA_PATH",
                 "cudaInitialized": False}
    return dict(_prepared)
