"""Optional, reversible cgroup-v2 response for confirmed high-confidence alerts."""

from __future__ import annotations

import os
from pathlib import Path

CGROUP_PATH = Path("/sys/fs/cgroup/kernel_sentinel_quarantine")


def setup_quarantine() -> None:
    """Create a cgroup with conservative CPU and memory limits."""
    CGROUP_PATH.mkdir(exist_ok=True)
    (CGROUP_PATH / "cpu.max").write_text("5000 100000", encoding="ascii")  # 5% of one core
    (CGROUP_PATH / "memory.max").write_text("50M", encoding="ascii")


def quarantine_pid(pid: int) -> bool:
    """Move a running PID into the constrained cgroup; returns success."""
    if os.geteuid() != 0:
        print("[QUARANTINE FAILED] pipeline must run as root")
        return False
    try:
        setup_quarantine()
        (CGROUP_PATH / "cgroup.procs").write_text(str(pid), encoding="ascii")
        print(f"[QUARANTINED] pid={pid}: CPU capped to 5%, memory capped to 50 MB")
        return True
    except (FileNotFoundError, OSError) as exc:
        print(f"[QUARANTINE FAILED] pid={pid}: {exc}")
        return False


def release_pid(pid: int) -> bool:
    """Return a false-positive process to the root cgroup."""
    try:
        Path("/sys/fs/cgroup/cgroup.procs").write_text(str(pid), encoding="ascii")
        print(f"[RELEASED] pid={pid}")
        return True
    except (FileNotFoundError, OSError) as exc:
        print(f"[RELEASE FAILED] pid={pid}: {exc}")
        return False
