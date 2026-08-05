# CURRENT STATUS

## Current milestone
M4 — Deterministic read replay

## Status
PASS

## What works
* Persistent Trace Format V2 introducing event kind 3 (`KernelMemoryWrite`) with full wire specification compliance.
* Backward compatibility for reading, parsing, and dumping Trace Format V1 files.
* Production recording (`causal record -o ...`) generating Trace Format V2 traces.
* Record-time capture of exact positive `SYS_read` output buffers from stopped tracee memory using `process_vm_readv`.
* Deterministic memory injection during replay writing recorded bytes to the LIVE buffer address using `process_vm_writev`.
* Replay-time suppression of live `SYS_read` via `orig_rax = -1` with `-ENOSYS` (`-38`) exit sentinel verification before injection.
* Proper handling of short reads: only capturing and injecting `result` bytes, preserving userspace buffer tail sentinels.
* Deterministic replay across deleted and modified external source files.
* Replay handling for EOF (`result = 0`), zero-byte count reads (`count = 0`), and failed reads (`result < 0`) with zero memory mutation.
* Strict syscall sequence matching (phase, syscall number, requested read count bounds) and complete event cursor consumption.
* Preservation of M3 `SYS_getpid` substitution, allowing mixed getpid and read replay in a single trace stream.
* Comprehensive pre-launch trace validation rejecting corrupt, incomplete, or unsupported V1/V2 files before target launch.
* Replay divergence detection with reliable child cleanup (`SIGKILL` + reap).

## What does not work
(Non-goals for M4):
* Full deterministic replay of arbitrary programs.
* Kernel file-description offset reconstruction or broader FD state tracking (suppressed reads do not advance kernel file offsets).
* Non-read memory outputs (`readv`, `pread64`, `recv`, `recvfrom`, `recvmsg`, `getrandom`, `ioctl`, etc.).
* Memory map lifecycle reconstruction (`mmap`, `munmap`, `mprotect`, `brk`).
* Signal delivery recording and replay.
* Multi-threaded / multi-process recording and replay.
* Automatic target binary discovery from trace metadata (target binary must be specified explicitly on replay CLI).

## Known limitations
* Linux x86-64 single-process, single-threaded native ELF targets only.
* Non-substituted syscalls execute live against host kernel and environment.
* Replay writes memory to the live buffer address captured from the live `SYS_read` entry; ASLR pointer addresses are not forced to match the recording.

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed (0 warnings).
* `cargo test` — Passed (49/49 unit and integration tests across M0, M1, M2, M3, and M4 suites).
* Flagship deleted-source behavioral verification:
  * Recorded `read_replay` fixture on external file (`21` bytes).
  * Deleted external file.
  * Native run exited `42` (negative control failed).
  * CAUSAL replay exited `0` (suppressed live read, injected 21 bytes into live buffer, verified tail sentinel `0xA5`, injected `RAX=21`).
* Modified-source verification: overwriting source file with corrupted data still resulted in successful replay exit `0`.
* EOF and error verification: empty file and `fd = -1` replayed deterministically with 0 memory mutation.
* Binary layout verification: manual hexdump decode of V2 header, `KernelMemoryWrite` record length, `source_event_id`, and payload.
* 100-run replay stress test against a single recorded trace with external file corrupted: 100/100 successful iterations.

## Current architecture
* `src/main.rs`: CLI entrypoint handling `record`, `dump`, and `replay`.
* `src/trace.rs`: Binary Trace Format V1/V2 codec, `TraceWriter`, `ParsedTrace`, and `dump_trace`.
* `src/tracer.rs`: Ptrace supervisor with remote memory reading (`read_process_memory_exact` via `process_vm_readv`) and shared lifecycle helpers.
* `src/replay.rs`: Deterministic replay engine with `SYS_getpid` / `SYS_read` suppression, live-buffer memory injection (`write_process_memory_exact` via `process_vm_writev`), `-ENOSYS` sentinel validation, and `RAX` return injection.
* `docs/adr/0001-trace-format-v1.md`: Trace Format V1 specification.
* `docs/adr/0002-x86-64-syscall-substitution.md`: x86-64 syscall suppression and return injection design.
* `docs/adr/0003-trace-format-v2-memory-write.md`: Trace Format V2 and `KernelMemoryWrite` design.

## Next exact task
M5 — Memory-map model
