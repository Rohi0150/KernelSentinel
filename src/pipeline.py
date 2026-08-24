#!/usr/bin/env python3
"""
Combined eBPF-to-ML detection pipeline.

This wires together everything built so far into one loop:
  eBPF tracer -> per-pid syscall window -> Random Forest inference -> response

The classifier is stored at ``ML_model/model/lid_ds_random_forest.joblib``.
It scores the latest per-PID window of all ten monitored syscalls.

Run with:
    sudo python3 pipeline.py
"""

from bcc import BPF
import ctypes as ct
import time
import json
import os
import uuid
from collections import defaultdict, deque
from pathlib import Path
import sys

from quarantine import quarantine_pid

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "ML_model"))
from model_runtime import LiveSyscallModel

# ---- Config ----
OUTPUT_DIR = os.path.expanduser("~/syscall_logs")
os.makedirs(OUTPUT_DIR, exist_ok=True)
TXT_PATH = os.path.join(OUTPUT_DIR, "syscall_trace.txt")
ALERT_PATH = os.path.join(OUTPUT_DIR, "anomaly_alerts.jsonl")

# One trace_id per run of this script — the ML model needs at least 3
# events sharing the same (trace_id, pid) to predict from, so this is
# assigned once at startup, not per-event.
TRACE_ID = f"run_{uuid.uuid4().hex[:8]}"

MODEL_PATH = Path(os.environ.get("ML_MODEL_PATH", PROJECT_ROOT / "ML_model" / "model" / "lid_ds_random_forest_runtime.json"))
MODEL_THRESHOLD = float(os.environ.get("MODEL_THRESHOLD", "0.50"))
# Alert-first is the safe default. Set AUTO_QUARANTINE=1 only after testing.
AUTO_QUARANTINE = os.environ.get("AUTO_QUARANTINE", "0") == "1"

# ---- eBPF program (same hooks as trace_syscalls.py) ----
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 syscall_id;   // 0=execve 1=connect 2=ptrace 3=setuid 4=dup2
                       // 5=openat 6=unlinkat 7=chmod 8=socket 9=clone
    char comm[TASK_COMM_LEN];
};

BPF_RINGBUF_OUTPUT(events, 8);

static int submit(u32 syscall_id) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = syscall_id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    events.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve)   { return submit(0); }
TRACEPOINT_PROBE(syscalls, sys_enter_connect)  { return submit(1); }
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace)   { return submit(2); }
TRACEPOINT_PROBE(syscalls, sys_enter_setuid)   { return submit(3); }
TRACEPOINT_PROBE(syscalls, sys_enter_dup2)     { return submit(4); }
TRACEPOINT_PROBE(syscalls, sys_enter_openat)   { return submit(5); }
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) { return submit(6); }
TRACEPOINT_PROBE(syscalls, sys_enter_chmod)    { return submit(7); }
TRACEPOINT_PROBE(syscalls, sys_enter_socket)   { return submit(8); }
TRACEPOINT_PROBE(syscalls, sys_enter_clone)    { return submit(9); }
"""

SYSCALL_NAMES = {
    0: "execve", 1: "connect", 2: "ptrace", 3: "setuid", 4: "dup2",
    5: "openat", 6: "unlinkat", 7: "chmod", 8: "socket", 9: "clone",
}


class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("syscall_id", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


# Per-pid rolling windows are initialized after loading the model so their
# length always matches the saved training artifact.
pid_sequences = {}
# Per-pid process name, so we can log it even after the process is gone
pid_names = {}
# Avoid re-quarantining a pid we've already flagged
already_flagged = set()
model = None


def is_anomalous(sequence):
    """Return the model verdict, probability, and explanation."""
    return model.score(sequence)


def handle_event(ctx, data, size, txt_file, alert_file):
    event = ct.cast(data, ct.POINTER(Event)).contents
    ts_ns = time.time_ns()
    syscall_name = SYSCALL_NAMES.get(event.syscall_id, "unknown")
    process_name = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]

    record = {
        "trace_id": TRACE_ID,
        "pid": event.pid,
        "process_name": process_name,
        "timestamp_ns": ts_ns,
        "syscall": syscall_name,
    }
    # --- update per-pid sequence buffer ---
    sequence = pid_sequences.setdefault(event.pid, deque(maxlen=model.window_size))
    sequence.append(record)
    pid_names[event.pid] = process_name

    # --- check for anomaly ---
    flagged, probability, reason = False, 0.0, None
    if event.pid not in already_flagged:
        flagged, probability, reason = is_anomalous(sequence)
    record["attack_probability"] = round(probability, 4)
    print(record)
    txt_file.write(json.dumps(record) + "\n")
    txt_file.flush()
    if flagged:
        already_flagged.add(event.pid)
        alert = {**record, "reason": reason, "action": "quarantine" if AUTO_QUARANTINE else "alert_only",
                 "syscall_window": [item["syscall"] for item in sequence]}
        alert_file.write(json.dumps(alert) + "\n")
        alert_file.flush()
        print(f"\n*** ML ALERT *** pid={event.pid} process={process_name} reason=\"{reason}\"")
        if AUTO_QUARANTINE:
            quarantine_pid(event.pid)
        print()


def main():
    global model
    if os.geteuid() != 0:
        print("Must run as root (sudo python3 pipeline.py).")
        return

    try:
        model = LiveSyscallModel(MODEL_PATH, threshold=MODEL_THRESHOLD)
    except (FileNotFoundError, ValueError, OSError, ModuleNotFoundError) as exc:
        print(f"Cannot load ML model at {MODEL_PATH}: {exc}")
        return
    print(f"Loaded Random Forest model: {MODEL_PATH}; window={model.window_size}; threshold={MODEL_THRESHOLD:.2f}")
    b = BPF(text=bpf_text)
    txt_file = open(TXT_PATH, "a")
    alert_file = open(ALERT_PATH, "a")

    b["events"].open_ring_buffer(
        lambda ctx, data, size: handle_event(ctx, data, size, txt_file, alert_file)
    )

    print(f"Pipeline running. Events: {TXT_PATH}; alerts: {ALERT_PATH}. "
          f"Auto-quarantine: {AUTO_QUARANTINE}. Ctrl-C to stop.\n")

    while True:
        try:
            b.ring_buffer_poll()
            time.sleep(0.01)
        except KeyboardInterrupt:
            print("\nStopped.")
            break

    txt_file.close()
    alert_file.close()


if __name__ == "__main__":
    main()
