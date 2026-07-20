# CURRENT STATUS

## Current milestone
M0 — Lifecycle & ptrace foundations

## Status
PASS

## What works
* Basic CLI handling `run` command.
* Process spawning under ptrace with `PTRACE_TRACEME` and error pipe reporting.
* Capturing normal exit status and signal termination.
* Forwarding arguments to target executable.

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed.
* `cargo test` — 7 passed (m0_lifecycle).

## Next exact task
M1 — Syscall tracing
