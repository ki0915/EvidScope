"""Wait for the controller's per-container cache reclaim configuration."""
import os
from pathlib import Path
import time


def wait_for_controller():
    if os.environ.get("EVIDSCOPE_MEMORY_HIGH_REQUIRED") != "1":
        raise RuntimeError("memory_high_controller_required")
    deadline = time.monotonic() + 90
    while not Path("/tmp/controller-memory-ready").exists():
        if time.monotonic() > deadline:
            raise RuntimeError("memory_high_controller_timeout")
        time.sleep(0.2)
    high = Path("/sys/fs/cgroup/memory.high").read_text().strip()
    maximum = Path("/sys/fs/cgroup/memory.max").read_text().strip()
    if high != str(2 * 1024 ** 3) or maximum != str(12 * 1024 ** 3):
        raise RuntimeError("memory_high_limit_mismatch")
