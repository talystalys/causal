# CURRENT STATUS

## Current milestone
M3 — First deterministic substitution

## Status
PASS

## What works
* `SYS_getpid` substitution replay prototype via `causal replay <trace> <program> [args...]`.
* Pre-launch trace validation ensuring single-TID and valid `SYS_getpid` substitution records prior to process fork.
* Strict syscall event sequence matching (phase, syscall number, event ordering) between live execution and recorded V1 trace.
* Native x86-64 syscall suppression at ENTRY stop by modifying `orig_rax` to `-1` via `PTRACE_SETREGS`.
* Verification of `-ENOSYS` (`-38`) suppression sentinel at EXIT stop before value injection.
* Injected recorded return value into `RAX` at EXIT stop, enabling tracee to observe the recorded PID across differing live PIDs.
* Passthrough execution of all other non-substituted syscalls against host kernel.
* Explicit divergence detection (wrong target, out-of-order syscalls, premature termination, extra live events) with reliable process cleanup (`SIGKILL` + reap).
* Rejection of unexpected signal delivery stops or ptrace events during replay.
* Full preservation of M0, M1, and M2 features (`record`, `record -o`, `dump`, error pipes, signal preservation during recording).

## What does not work
(Non-goals for M3):
* Full deterministic replay of arbitrary programs.
* Non-getpid syscall substitution (`getppid`, `clock_gettime`, `read`, etc.).
* Userspace memory output replay / buffer mutation (deferred to M4).
* Signal delivery recording and replay.
* Multi-threaded / multi-process replay.
* Automatic target binary discovery from trace metadata (target binary must be specified explicitly).

## Known limitations
* Linux x86-64 single-process, single-threaded native ELF targets only.
* Non-substituted syscalls execute live against host kernel and environment (ASLR addresses and return values may differ across runs).
* Replay trace must strictly match Trace Format V1.

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed (0 warnings).
* `cargo test` — Passed (40/40 unit and integration tests across M0, M1, M2, and M3 suites).
* Behavioral proof on `getpid_replay` fixture:
  * Native run with `CAUSAL_EXPECT_GETPID=<recorded_pid>` exited `42` (live PID != recorded PID).
  * CAUSAL replay with `CAUSAL_EXPECT_GETPID=<recorded_pid>` exited `0` (recorded PID successfully injected into `RAX`).
  * Live replay PID differed from recorded PID; pre-injection exit result was verified as `-38` (`-ENOSYS`).
* Wrong-target divergence testing (`write_hello` against `getpid_replay` trace): cleanly aborted with divergence diagnostic and child reaped.
* Pre-launch corruption testing: corrupt trace rejected before target fork.
* 100-run replay stress test against single recorded trace: 100/100 successful iterations.

## Current architecture
* `src/main.rs`: CLI entrypoint handling `record`, `dump`, and `replay`.
* `src/trace.rs`: Binary Trace Format V1 codec, `TraceWriter`, `read_trace_file`, and `dump_trace`.
* `src/tracer.rs`: Ptrace supervisor with shared lifecycle helpers (`launch_traced_child`, `kill_and_reap`, `get_regs_x86_64`, `set_regs_x86_64`, `get_syscall_info`).
* `src/replay.rs`: Deterministic replay engine with event sequence matching, `SYS_getpid` suppression, `-ENOSYS` sentinel validation, and `RAX` return value injection.
* `docs/adr/0001-trace-format-v1.md`: Trace Format V1 specification.
* `docs/adr/0002-x86-64-syscall-substitution.md`: x86-64 syscall suppression and return injection design.

## Next exact task
M4 — Deterministic read replay
