# Milestone M0 Verification Report

## Environment

* **OS:** Linux
* **Kernel Version:** `6.18.43_1 #1 SMP PREEMPT_DYNAMIC Sat Aug 8 00:50:08 UTC 2026`
* **Architecture:** `x86_64`
* **Rust Compiler:** `rustc 1.97.1 (8bab26f4f 2026-07-14) (Void Linux)`
* **Cargo:** `cargo 1.97.0`
* **C Compiler:** `cc (GCC) 14.2.1 20250405`
* **Yama ptrace scope:** `1`

## Commands Actually Executed

### 1. Build and Code Quality
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### 2. Fixture Compilation
```bash
./scripts/build-fixtures.sh
```

### 3. Normal Exit Fixture (`exit_42`)
```bash
./target/debug/causal record ./tests/bin/exit_42
echo "Exit code: $?"
```

### 4. Signal Termination Fixture (`signal_term`)
```bash
./target/debug/causal record ./tests/bin/signal_term
echo "Exit code: $?"
```

### 5. Nonexistent Executable Failure Case
```bash
./target/debug/causal record ./tests/bin/definitely-does-not-exist
echo "Exit code: $?"
```

### 6. Permission-Denied Executable Failure Case
```bash
touch /tmp/causal-m0-nonexec && chmod 0644 /tmp/causal-m0-nonexec
./target/debug/causal record /tmp/causal-m0-nonexec
echo "Exit code: $?"
rm -f /tmp/causal-m0-nonexec
```

### 7. Invalid CLI Invocations
```bash
./target/debug/causal; echo "Exit code: $?"
./target/debug/causal record; echo "Exit code: $?"
./target/debug/causal nonsense ./tests/bin/exit_42; echo "Exit code: $?"
```

### 8. Target Arguments Passthrough
```bash
./target/debug/causal record /bin/sh -c 'echo "hello from child with args"; exit 42'
echo "Exit code: $?"
```

### 9. 100-Run Lifecycle Repetition under Timeout Protection
```bash
timeout 10s bash -c 'for i in $(seq 1 100); do ./target/debug/causal record ./tests/bin/exit_42 >/tmp/causal-m0.out 2>/tmp/causal-m0.err; rc=$?; test "$rc" -eq 42 || (echo "Failed at iteration $i with rc $rc" && exit 1); done && echo "100 iterations passed successfully"'
```

### 10. Zombie / Defunct Process Audit
```bash
ps aux | grep '[d]efunct'
ps -ef | grep '[c]ausal'
```

---

## Results

| Acceptance Case | Result | Raw Output / Evidence |
| :--- | :--- | :--- |
| **A. `causal record` launches fixture under ptrace** | **PASS** | Child executed and traced via `PTRACE_TRACEME` |
| **B. Startup stop observed & handled** | **PASS** | Deliberate `raise(SIGSTOP)` caught by parent `waitpid` and consumed |
| **C. Initial exec positively recognized** | **PASS** | Configured `PTRACE_O_TRACEEXEC` and matched `PTRACE_EVENT_EXEC` in `waitpid` |
| **D. Normal exit reported** | **PASS** | `child exited with status 42` |
| **E. Exit code propagated** | **PASS** | Exit code: `42` |
| **F. SIGTERM not swallowed** | **PASS** | Process terminated by `SIGTERM` (signal 15), did not reach return `99` |
| **G. Signal termination reported** | **PASS** | `child terminated by signal 15`, exit code `143` (128 + 15) |
| **H. Nonexistent target launch failure recognized** | **PASS** | `causal: launch failed: exec failed for './tests/bin/definitely-does-not-exist': No such file or directory (os error 2)` (exit code 1) |
| **I. Non-executable target launch failure recognized** | **PASS** | `causal: launch failed: exec failed for '/tmp/causal-m0-nonexec': Permission denied (os error 13)` (exit code 1) |
| **J. Invalid CLI input fails cleanly** | **PASS** | Usage printed to stderr, exit code `2`, no panic |
| **K. No required case panics** | **PASS** | All failure modes handled via `Result` / `eprintln` |
| **L. No required case hangs** | **PASS** | All tests completed in <1s with external timeout protection |
| **M. Child reaped cleanly** | **PASS** | `waitpid` reaps process on exit/signal; 0 defunct/zombie processes |
| **N. 100-run repetition test** | **PASS** | `100 iterations passed successfully` (0 flakes or hangs) |
| **O. `cargo test` passes** | **PASS** | `7 passed; 0 failed; 0 ignored; finished in 0.51s` |
| **P. `CURRENT_STATUS.md` accurate** | **PASS** | Updated to reflect verified M0 milestone |
| **Q. Verification report complete** | **PASS** | Recorded in `docs/reports/m0-verification.md` |
| **R. No M1 functionality implemented** | **PASS** | No syscall interception, no event format, no replay |

---

## Architecture Implemented

1. **Pre-fork Argument Preparation:** Target path and argument strings are converted into `CString` instances and null-terminated raw pointer vectors in the parent prior to `fork()` to maintain async-signal-safety between `fork()` and `execvp()`.
2. **Launch Error Channel:** An anonymous pipe is created with `libc::pipe2(..., O_CLOEXEC)`. The child retains the write descriptor. If `PTRACE_TRACEME`, `raise(SIGSTOP)`, or `execvp` fails, the child writes a structured `LaunchErrorPayload { stage, errno }` and terminates via `_exit(127)`. When `execvp` succeeds, `O_CLOEXEC` automatically closes the pipe, resulting in EOF on the parent's read descriptor.
3. **Tracee Initialization & Startup Synchronization:** The child invokes `PTRACE_TRACEME` and raises `SIGSTOP`. The parent calls `waitpid()` to intercept the deliberate startup stop.
4. **Exec Event Tracking:** The parent configures `PTRACE_O_TRACEEXEC` via `PTRACE_SETOPTIONS` and resumes the child with signal 0 (`PTRACE_CONT`). The parent waits for `waitpid()` and checks the launch pipe. On EOF, it validates `PTRACE_EVENT_EXEC` (`(status >> 16) == PTRACE_EVENT_EXEC`), positively confirming successful exec.
5. **Tracee Resumption:** The parent resumes the debuggee with signal 0 to consume the exec trap.
6. **Signal Reinjection & Event Loop:** The parent enters a `waitpid()` event loop:
   * Normal termination (`WIFEXITED`): Decodes exit code, prints `child exited with status N`, and exits with `N`.
   * Signal termination (`WIFSIGNALED`): Decodes signal, prints `child terminated by signal N`, and exits with `128 + N`.
   * Signal-delivery stop (`WIFSTOPPED` with no ptrace event bits): Re-injects the stop signal via `PTRACE_CONT(pid, stop_sig)` to preserve standard signal behavior (e.g. `SIGTERM`).
   * Unexpected stops/events: Generates a detailed diagnostic with raw wait status and aborts cleanly.
7. **Child Reaping:** The tracee is reaped directly by `waitpid()` on termination.

---

## Known Limitations

* Only single-process, single-threaded Linux x86-64 native ELF targets are supported in M0.
* Syscall tracing (`PTRACE_SYSCALL`) is out of scope for M0 and deferred to M1.
* Any ptrace event stops other than initial exec trigger an explicit error diagnostic.

---

## Final M0 Classification

**PASS**
