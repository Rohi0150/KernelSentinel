#!/usr/bin/env python3
"""
Combined detection pipeline (placeholder version).

This wires together everything built so far into one loop:
  eBPF tracer -> per-pid syscall sequence buffer -> anomaly check -> quarantine

The anomaly check here is a PLACEHOLDER pattern-match (not real ML) so you
have a working end-to-end demo today. Once your ML teammate's model is
ready, swap out `is_anomalous()` for a call to their scoring function —
everything else (buffering, extraction, quarantine trigger) stays the same.

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

from quarantine import quarantine_pid

# ---- Config ----
OUTPUT_DIR = os.path.expanduser("~/syscall_logs")
os.makedirs(OUTPUT_DIR, exist_ok=True)
TXT_PATH = os.path.join(OUTPUT_DIR, "syscall_trace.txt")

# One trace_id per run of this script — the ML model needs at least 3
# events sharing the same (trace_id, pid) to predict from, so this is
# assigned once at startup, not per-event.
TRACE_ID = f"run_{uuid.uuid4().hex[:8]}"

SEQ_WINDOW = 10          # how many recent syscalls to keep per pid
AUTO_QUARANTINE = True   # set False to just print alerts without acting

# Syscalls that are "signal" for the reverse-shell pattern check.
# Excludes high-frequency noise (openat, clone) that would otherwise
# push connect/dup2/execve out of a short rolling window before they
# can be matched together.
SIGNAL_SYSCALLS = {"connect", "dup2", "execve", "socket", "ptrace", "setuid"}

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


# Per-pid rolling window of recent syscalls: { pid: deque([...]) }
pid_sequences = defaultdict(lambda: deque(maxlen=SEQ_WINDOW))
# Per-pid process name, so we can log it even after the process is gone
pid_names = {}
# Avoid re-quarantining a pid we've already flagged
already_flagged = set()


def is_anomalous(pid, sequence):
    """
    PLACEHOLDER anomaly check — replace this with your ML teammate's
    real scoring function once it's ready. For now: flags the classic
    reverse-shell pattern (connect -> dup2 -> execve appearing in order,
    anywhere in the recent window).
    """
    seq = list(sequence)
    try:
        i = seq.index("connect")
        j = seq.index("dup2", i + 1)
        seq.index("execve", j + 1)
        return True, "connect -> dup2 -> execve pattern (reverse-shell signature)"
    except ValueError:
        return False, None


def handle_event(ctx, data, size, txt_file):
    event = ct.cast(data, ct.POINTER(Event)).contents
    ts_ns = time.time_ns()
    syscall_name = SYSCALL_NAMES.get(event.syscall_id, "unknown")
    process_name = event.comm.decode("utf-8", "replace")

    record = {
        "trace_id": TRACE_ID,
        "pid": event.pid,
        "process_name": process_name,
        "timestamp_ns": ts_ns,
        "syscall": syscall_name,
    }
    print(record)
    txt_file.write(json.dumps(record) + "\n")
    txt_file.flush()

    # --- update per-pid sequence buffer ---
    # Only feed "signal" syscalls into the detection window, so a burst
    # of unrelated openat/clone calls (e.g. bash loading libraries)
    # doesn't push connect/dup2/execve out of the window before they
    # can be matched together.
    if syscall_name in SIGNAL_SYSCALLS:
        pid_sequences[event.pid].append(syscall_name)
    pid_names[event.pid] = process_name

    # --- check for anomaly ---
    if event.pid not in already_flagged:
        flagged, reason = is_anomalous(event.pid, pid_sequences[event.pid])
        if flagged:
            already_flagged.add(event.pid)
            print(f"\n*** ANOMALY DETECTED *** pid={event.pid} "
                  f"process={process_name} reason=\"{reason}\"")
            if AUTO_QUARANTINE:
                quarantine_pid(event.pid)
            print()


def main():
    if os.geteuid() != 0:
        print("Must run as root (sudo python3 pipeline.py).")
        return

    b = BPF(text=bpf_text)
    txt_file = open(TXT_PATH, "a")

    b["events"].open_ring_buffer(
        lambda ctx, data, size: handle_event(ctx, data, size, txt_file)
    )

    print(f"Pipeline running. Logging to {TXT_PATH}. "
          f"Auto-quarantine: {AUTO_QUARANTINE}. Ctrl-C to stop.\n")

    while True:
        try:
            b.ring_buffer_poll()
            time.sleep(0.01)
        except KeyboardInterrupt:
            print("\nStopped.")
            break

    txt_file.close()


if __name__ == "__main__":
    main()
