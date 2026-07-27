# CURRENT STATUS

## Current milestone
M2 — Versioned trace format

## Status
PASS

## What works
* Streaming syscall events (`SyscallEnter`, `SyscallExit`) to persistent V1 binary trace files via `causal record -o <trace> <program> [args...]`.
* Preserving live console observation mode via `causal record <program> [args...]`.
* Parsing and dumping trace files via `causal dump <trace>`.
* Binary wire format V1 with 16-byte header (`CAUSAL\0\0`, version 1, x86-64, little-endian, 64-bit pointer width).
* Framed event records with 4-byte length prefixes, monotonic 64-bit event IDs, 32-bit TIDs, 6 raw 64-bit syscall arguments, and 64-bit signed return results.
* 16-byte completion footer (`event_count` + `CAUSEND\0` magic) guaranteeing complete recordings.
* Comprehensive corruption and validation checks (magic, version, arch, endianness, non-monotonic event IDs, bad record lengths, truncated files, trailing garbage, count mismatches).
* Automatic cleanup of incomplete trace files on launch failures.
* Full preservation of M0 and M1 capabilities (signal preservation, exec error pipe, exit code propagation, process reaping).

## What does not work
(Non-goals for M2):
* Deterministic replay / execution replaying.
* Syscall modification / return value substitution (deferred to M3).
* Userspace memory payload capture / pointer dereferencing (deferred to M4).
* Multi-threaded / multi-process tracing.

## Known limitations
* Linux x86-64 single-process, single-threaded native ELF targets only.
* Raw register representation only (no userspace pointer dereferencing or syscall name database).
* Traces are specific to format version 1 (unknown versions are rejected).

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed (0 warnings).
* `cargo test` — Passed (34/34 unit and integration tests across M0, M1, and M2 suites).
* Hexdump / binary layout inspection verifying exact byte offsets and little-endian wire encoding.
* Synthetic deterministic serialization test confirming byte-for-byte identical encoding.
* Round-trip record and dump verification for deliberate `write_hello` fixture (`SYS_write`, `fd=1`, `count=6`, `result=6`).
* CLI corruption testing (bad magic, unsupported version, truncated trace, missing footer, trailing garbage).
* Automatic cleanup of incomplete trace on launch failure.
* 100-run record and dump stress test under timeout protection: 100/100 successful iterations.

## Current architecture
* `src/main.rs`: CLI dispatcher supporting `record [-o <trace>] <program> [args...]` and `dump <trace>`.
* `src/trace.rs`: Binary trace format V1 codec, `TraceWriter`, `TraceEvent`, `parse_trace_bytes`, and `dump_trace`.
* `src/tracer.rs`: Ptrace lifecycle supervisor with live console observation and streaming `TraceWriter` integration.
* `docs/adr/0001-trace-format-v1.md`: Architecture Decision Record for Trace Format V1.

## Next exact task
M3 — First deterministic substitution
