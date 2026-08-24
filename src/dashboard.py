#!/usr/bin/env python3
"""
Live syscall dashboard — a "btop for our syscalls."

Shows a continuously updating terminal table: one row per active process,
columns = counts of each monitored syscall, plus a STATUS column that
flips to ANOMALY / QUARANTINED when the pipeline's detector fires.

This is NOT a general eBPF program monitor (that's what bpftop does) —
it's a live view tailored specifically to our 10 tracked syscalls and
our own detection pipeline, which doesn't exist as an off-the-shelf tool.

Run with:
    sudo python3 dashboard.py

Quit with 'q'.
"""

from bcc import BPF
import ctypes as ct
import curses
import time
import os
import json
import uuid
from collections import defaultdict, deque
from pathlib import Path
import sys

from quarantine import quarantine_pid

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "ML_model"))
from model_runtime import LiveSyscallModel

TRACE_ID = f"run_{uuid.uuid4().hex[:8]}"

MODEL_PATH = Path(os.environ.get("ML_MODEL_PATH", PROJECT_ROOT / "ML_model" / "model" / "lid_ds_random_forest_runtime.json"))
MODEL_THRESHOLD = float(os.environ.get("MODEL_THRESHOLD", "0.50"))
AUTO_QUARANTINE = os.environ.get("AUTO_QUARANTINE", "0") == "1"
MAX_ROWS = 20            # most recent/active processes shown at once
STALE_AFTER_SEC = 15      # rows drop off if no activity for this long

OUTPUT_DIR = os.path.expanduser("~/syscall_logs")
os.makedirs(OUTPUT_DIR, exist_ok=True)
TXT_PATH = os.path.join(OUTPUT_DIR, "syscall_trace.txt")

# ---- eBPF program (same hooks as pipeline.py) ----
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

SYSCALL_NAMES = [
    "execve", "connect", "ptrace", "setuid", "dup2",
    "openat", "unlinkat", "chmod", "socket", "clone",
]


class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("syscall_id", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


# --- shared state, updated by the eBPF callback, read by the UI loop ---
class ProcState:
    __slots__ = ("name", "counts", "last_seen", "events", "status", "probability")

    def __init__(self, name):
        self.name = name
        self.counts = defaultdict(int)   # syscall_name -> count
        self.last_seen = time.time()
        self.events = deque()
        self.status = "normal"           # normal | anomaly | quarantined
        self.probability = 0.0


procs = {}          # pid -> ProcState
already_flagged = set()
model = None


def is_anomalous(events):
    """Use the same Random Forest inference as the live pipeline."""
    return model.score(events)


def handle_event(ctx, data, size, txt_file):
    event = ct.cast(data, ct.POINTER(Event)).contents
    syscall_name = SYSCALL_NAMES[event.syscall_id] if event.syscall_id < len(SYSCALL_NAMES) else "unknown"
    process_name = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]

    # log every event to file, same format as pipeline.py / trace_syscalls.py
    record = {
        "trace_id": TRACE_ID,
        "pid": event.pid,
        "process_name": process_name,
        "timestamp_ns": time.time_ns(),
        "syscall": syscall_name,
    }
    txt_file.write(json.dumps(record) + "\n")
    txt_file.flush()

    p = procs.get(event.pid)
    if p is None:
        p = ProcState(process_name)
        procs[event.pid] = p

    p.name = process_name
    p.counts[syscall_name] += 1
    p.last_seen = time.time()
    p.events.append(record)
    while len(p.events) > model.window_size:
        p.events.popleft()

    if event.pid not in already_flagged:
        flagged, probability, reason = is_anomalous(p.events)
        p.probability = probability
        if flagged:
            already_flagged.add(event.pid)
            p.status = "anomaly"
            if AUTO_QUARANTINE:
                quarantine_pid(event.pid)
                p.status = "quarantined"


def draw(stdscr, b):
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # normal
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # anomaly
    curses.init_pair(3, curses.COLOR_RED, -1)     # quarantined
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # header

    col_names = SYSCALL_NAMES

    while True:
        # drain any pending eBPF events (non-blocking-ish, small timeout)
        try:
            b.ring_buffer_poll(timeout=1)
        except Exception:
            pass

        # handle quit key
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q')):
            break

        now = time.time()
        # drop stale rows
        for pid in [p for p, s in procs.items() if now - s.last_seen > STALE_AFTER_SEC]:
            del procs[pid]

        stdscr.erase()
        h, w = stdscr.getmaxyx()

        title = " LIVE SYSCALL MONITOR — 'q' to quit "
        stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        stdscr.addnstr(0, 0, title.center(w), w)
        stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

        # header row
        header = f"{'PID':>7}  {'PROCESS':<16}  " + "  ".join(f"{n[:6]:>6}" for n in col_names) + f"  {'SCORE':>6}  {'STATUS':<12}"
        stdscr.attron(curses.A_BOLD)
        stdscr.addnstr(2, 0, header[:w], w)
        stdscr.attroff(curses.A_BOLD)

        # sort: quarantined/anomaly first, then most recently active
        rows = sorted(
            procs.items(),
            key=lambda kv: (kv[1].status == "normal", -kv[1].last_seen),
        )[:MAX_ROWS]

        row_y = 3
        for pid, s in rows:
            if row_y >= h - 1:
                break
            counts_str = "  ".join(f"{s.counts.get(n, 0):>6}" for n in col_names)
            line = f"{pid:>7}  {s.name[:16]:<16}  {counts_str}  {s.probability:>6.2f}  {s.status:<12}"

            if s.status == "quarantined":
                color = curses.color_pair(3) | curses.A_BOLD
            elif s.status == "anomaly":
                color = curses.color_pair(2) | curses.A_BOLD
            else:
                color = curses.color_pair(1)

            stdscr.attron(color)
            stdscr.addnstr(row_y, 0, line[:w], w)
            stdscr.attroff(color)
            row_y += 1

        stdscr.addnstr(h - 1, 0, f" tracked pids: {len(procs)}   auto-quarantine: {AUTO_QUARANTINE} ", w)
        stdscr.refresh()
        time.sleep(0.05)


def main():
    global model
    if os.geteuid() != 0:
        print("Must run as root (sudo python3 dashboard.py).")
        return

    try:
        model = LiveSyscallModel(MODEL_PATH, threshold=MODEL_THRESHOLD)
    except (FileNotFoundError, ValueError, OSError, ModuleNotFoundError) as exc:
        print(f"Cannot load ML model at {MODEL_PATH}: {exc}")
        return
    b = BPF(text=bpf_text)
    txt_file = open(TXT_PATH, "a")
    b["events"].open_ring_buffer(lambda ctx, data, size: handle_event(ctx, data, size, txt_file))

    try:
        curses.wrapper(lambda stdscr: draw(stdscr, b))
    finally:
        txt_file.close()


if __name__ == "__main__":
    main()
