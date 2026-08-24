#!/usr/bin/env python3
"""
Starter syscall tracer for kernel-level behavioral drift detection.

Traces execve, connect, ptrace, setuid, dup2, openat, unlinkat, chmod,
socket, clone syscalls, printing/logging:
  timestamp | pid | process name | syscall

Requires: bcc installed on a real Linux machine (not this sandbox).
Install on Ubuntu/Debian:
    sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

Run with:
    sudo python3 trace_syscalls.py
"""

from bcc import BPF
import ctypes as ct
import time
import json
import struct
import os
import uuid

TRACE_ID = f"run_{uuid.uuid4().hex[:8]}"

# ---- Output file settings ----
# Text format: one JSON object per line -> easy for ML side to read with pandas/json
# Binary format: fixed-size binary records -> smaller, faster, but needs a matching reader
OUTPUT_FORMAT = "txt"   # change to "bin" for binary output
OUTPUT_DIR = os.path.expanduser("~/syscall_logs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

TXT_PATH = os.path.join(OUTPUT_DIR, "syscall_trace.txt")
BIN_PATH = os.path.join(OUTPUT_DIR, "syscall_trace.bin")

# Binary record layout: pid (u32) + syscall_id (u32) + comm (16 bytes, null-padded)
BIN_STRUCT_FMT = "=II16s"
BIN_RECORD_SIZE = struct.calcsize(BIN_STRUCT_FMT)

# ---- eBPF program (runs in kernel space) ----
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event struct sent to userspace via ring buffer
struct event_t {
    u32 pid;
    u32 syscall_id;   // 0=execve 1=connect 2=ptrace 3=setuid 4=dup2
                       // 5=openat 6=unlinkat 7=chmod 8=socket 9=clone
    char comm[TASK_COMM_LEN];
};

BPF_RINGBUF_OUTPUT(events, 8);

// --- execve tracepoint ---
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- connect syscall (network outbound) ---
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 1;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- ptrace syscall (code injection / debugging abuse) ---
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 2;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- setuid syscall (privilege escalation) ---
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 3;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- dup2 syscall (fd redirection - reverse shell signal) ---
TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 4;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- openat syscall (file access - e.g. reading credentials/SSH keys) ---
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 5;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- unlinkat syscall (file deletion - e.g. ransomware / cover-tracking) ---
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 6;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- chmod syscall (permission changes - e.g. making a dropped file executable) ---
TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 7;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- socket syscall (socket creation - precedes connect/bind) ---
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 8;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}

// --- clone syscall (process spawning - e.g. malware forking children) ---
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));
    if (!event) return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->syscall_id = 9;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    events.ringbuf_submit(event, 0);
    return 0;
}
"""

# Map syscall_id back to a readable name
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


def handle_event(ctx, data, size, txt_file=None, bin_file=None):
    """Called for every event pulled off the ring buffer."""
    event = ct.cast(data, ct.POINTER(Event)).contents
    ts_ns = time.time_ns()
    syscall_name = SYSCALL_NAMES.get(event.syscall_id, "unknown")
    process_name = event.comm.decode("utf-8", "replace")

    # This is the structured record you'd hand off to the ML side.
    record = {
        "trace_id": TRACE_ID,
        "pid": event.pid,
        "process_name": process_name,
        "timestamp_ns": ts_ns,
        "syscall": syscall_name,
    }
    print(record)

    if txt_file is not None:
        # One JSON object per line -> easy to load with json.loads() per line,
        # or pandas.read_json(path, lines=True) on the ML side.
        txt_file.write(json.dumps(record) + "\n")
        txt_file.flush()

    if bin_file is not None:
        # Fixed-size binary record: pid, syscall_id, comm (16 bytes).
        # ML side reads BIN_RECORD_SIZE-byte chunks and unpacks with the same struct format.
        packed = struct.pack(BIN_STRUCT_FMT, event.pid, event.syscall_id, event.comm)
        bin_file.write(packed)
        bin_file.flush()


def main():
    b = BPF(text=bpf_text)

    txt_file = open(TXT_PATH, "a") if OUTPUT_FORMAT == "txt" else None
    bin_file = open(BIN_PATH, "ab") if OUTPUT_FORMAT == "bin" else None

    b["events"].open_ring_buffer(
        lambda ctx, data, size: handle_event(ctx, data, size, txt_file, bin_file)
    )

    out_path = TXT_PATH if OUTPUT_FORMAT == "txt" else BIN_PATH
    print(f"Tracing 10 syscalls (execve, connect, ptrace, setuid, dup2, "
          f"openat, unlinkat, chmod, socket, clone)... writing to {out_path}. Ctrl-C to stop.")
    while True:
        try:
            b.ring_buffer_poll()
            time.sleep(0.01)
        except KeyboardInterrupt:
            print("\nStopped.")
            break

    if txt_file:
        txt_file.close()
    if bin_file:
        bin_file.close()


if __name__ == "__main__":
    main()
