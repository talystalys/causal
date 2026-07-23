# CURRENT STATUS

## Current milestone
M1 — Syscall boundaries & observation

## Status
PASS

## What works
* Syscall entry and exit interception via `PTRACE_O_TRACESYSGOOD`.
* Syscall number and argument extraction using `PTRACE_GET_SYSCALL_INFO`.
* Tracking pending syscalls and validating strict entry/exit pairing.
* Accurate signed return values for syscall exit stops.
* Distinction between plain `SIGTRAP` and ptrace syscall stops.

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed.
* `cargo test` — 13 passed (7 m0_lifecycle + 6 m1_syscalls).

## Next exact task
M2 — Deterministic trace encoding & storage
