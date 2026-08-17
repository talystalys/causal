# CURRENT STATUS

## Current milestone
M6 — Signals

## Status
PASS

## What works
* Trace Format V4 (`format_version = 4`) introducing `SignalDelivery` (`event_kind = 7`).
* Recording-time non-syscall signal stop observation using `PTRACE_GETSIGINFO`.
* Recording and classification of `SI_USER` (0) and `SI_TKILL` (-6) signal deliveries with exact `siginfo_t` preservation.
* Distinction between plain `SIGTRAP` deliveries (`raise(SIGTRAP)`) and ptrace breakpoint traps.
* Deterministic signal replay synthesis using `libc::tgkill(pid, pid, signal_number)` while tracee is stopped at preceding event.
* Replay-side `PTRACE_SETSIGINFO` restoration restoring original `si_pid`, `si_uid`, `si_errno`, and `si_code` into target `SA_SIGINFO` signal handlers.
* Replay-side verification of siginfo restoration via `PTRACE_GETSIGINFO`.
* Full support for default-action signal terminations (e.g. `SIGTERM`) across both record and replay with CLI exit code `128 + sig`.
* Replay divergence detection for unrecorded live signals or unexpected signal numbers.
* Interleaved signal delivery and passthrough syscall execution (`SyscallEnter` -> `SignalDelivery` -> `SyscallExit`).
* Multiple signal deliveries within a single trace (`SIGUSR1` -> intervening syscall -> `SIGUSR2`).
* Mixed signal replay alongside `SYS_getpid` and `SYS_read` deterministic substitution.
* Strict V4 trace structural validation enforcing read-memory-write adjacency and map-delta contiguity across signal deliveries.
* Prelaunch rejection of unsupported signal numbers or codes before target process launch.
* V4 offline historical map queries via `causal maps <trace> <event-id>`.
* Clean rejection and immediate trace cleanup on unsupported stopping signals (`SIGSTOP`, `SIGTSTP`, `SIGCONT`) or synchronous hardware faults (`SIGSEGV`).
* Full backward compatibility for reading, parsing, dumping, and replaying Trace Format V1, V2, and V3 traces.

## What does not work
(Non-goals for M6):
* instruction-exact async signal timing
* full signal-frame/ucontext restoration
* signal interposition inside substituted SYS_getpid/SYS_read pairs
* group-stop
* SIGCONT semantics
* synchronous fault replay
* timer/AIO signal replay
* multi-thread signal routing
* real-time queue semantics

## Known limitations
* Linux x86-64 single-process, single-threaded native ELF targets only.
* Non-substituted syscalls execute live against host kernel and environment.
* Signal delivery timing is reproduced logically between syscall boundaries rather than at exact instruction cycle counts.
* Signal delivery interposed specifically inside substituted `SYS_getpid` or `SYS_read` pairs is rejected preflight.

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed (0 warnings).
* `cargo test` — Passed (90/90 unit and integration tests across M0, M1, M2, M3, M4, M5, and M6 suites).
* Flagship external `SIGUSR1` recording & replay (`signal_external_usr1.c`):
  * Observed live recording with external sender PID.
  * Verified 100% deterministic replay with zero external senders and preserved `SA_SIGINFO` sender PID.
* Default-action `SIGTERM` termination (`signal_external_term.c`): verified recording termination, valid completion footer, and replay synthesis resulting in CLI exit 143 (`128 + 15`).
* Multiple signals (`signal_multi_usr.c`): verified delivery and replay of consecutive `SIGUSR1` and `SIGUSR2` separated by `SYS_getpid`.
* Structural pairing invariance: verified synthetic traces interleaving `SyscallEnter -> SignalDelivery -> SyscallExit`.
* Read memory write adjacency & map delta contiguity: strictly rejected malformed traces interleaving signal events before required memory writes or breaking delta contiguity.
* Prelaunch validation: verified prelaunch rejection of unsupported signals and interposed substituted pairs.
* Comprehensive corruption coverage: verified 15 synthetic parser corruption cases across V1, V2, V3, and V4 formats.
* Unsupported signal rejection (`signal_stop_unsupported.c` and `signal_segv_unsupported.c`): verified clean failure and incomplete trace cleanup.
* V4 deterministic binary serialization: verified bit-for-bit identical binary output for repeated V4 synthetic streams.
* 100-run replay stress test: 100/100 consecutive successful replays of external `SIGUSR1` trace with zero external signals.

## Current architecture
* `src/main.rs`: CLI entrypoint handling `record`, `dump`, `replay`, and `maps`.
* `src/maps.rs`: Virtual memory map model and procfs maps parsing.
* `src/trace.rs`: Binary Trace Format V1/V2/V3/V4 codec, `TraceWriter`, `ParsedTrace`, structural validation, and historical maps reconstruction.
* `src/tracer.rs`: Ptrace supervisor with signal stop classification (`PTRACE_GETSIGINFO`), trace serialization, and child lifecycle management.
* `src/replay.rs`: Deterministic replay engine with `tgkill` signal arming, `PTRACE_SETSIGINFO` restoration, preflight validation, syscall suppression, and memory injection.
* `docs/adr/0001-trace-format-v1.md`: Trace Format V1 specification.
* `docs/adr/0002-x86-64-syscall-substitution.md`: x86-64 syscall suppression and return injection design.
* `docs/adr/0003-trace-format-v2-memory-write.md`: Trace Format V2 and `KernelMemoryWrite` design.
* `docs/adr/0004-memory-map-model-and-trace-v3.md`: Trace Format V3 and Virtual Memory-Map Model design.
* `docs/adr/0005-signal-delivery-and-trace-v4.md`: Trace Format V4 and Signal Delivery design.
* `docs/reports/m6-verification.md`: Milestone M6 verification report.

## Next exact task
M7 — Multi-process / exec lifecycle
