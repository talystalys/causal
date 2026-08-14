# ADR 0005: Signal Delivery and Trace Format V4 Specification

## Status
Accepted

## Context
CAUSAL is a deterministic record/replay debugger for Linux x86-64 single-threaded ELF processes. In real-world software, processes interact with asynchronous and synchronous Linux signals: process lifecycle controls (`SIGTERM`, `SIGINT`), inter-process notifications (`SIGUSR1`, `SIGUSR2`), timer events, and exception traps (`SIGTRAP`).

Prior to Milestone M6, CAUSAL observed only ptrace syscall entry and exit stops (`PTRACE_SYSCALL_INFO_ENTRY` and `PTRACE_SYSCALL_INFO_EXIT`). Non-syscall stops caused by signal delivery either caused fatal replay divergence or were not captured in the persistent execution trace.

Milestone M6 introduces first-class recording and deterministic replay of signal-delivery stops, capturing precise `siginfo_t` metadata and synthesizing signals during replay.

---

## Decision

We introduce **CAUSAL Trace Format V4** featuring a dedicated event kind:
* `SignalDelivery` (`event_kind = 7`)

### 1. Versioning & Compatibility Policy
* **V3 Format Freeze:** Trace Format V3 is immutable. Adding `event_kind = 7` without incrementing `format_version` would violate backward compatibility with V3 parsers that reject unknown event kinds.
* **Trace Format V4 (`format_version = 4`):** Produced by default for all new recordings via `causal record -o <trace> ...` and `TraceWriter::new_v4`.
* **Reader Compatibility:** Decodes all historical versions (V1, V2, V3) and V4.
* **Replay Compatibility:** Replays V1, V2, V3, and V4 traces. V4 traces with `SignalDelivery` events are replayed deterministically without requiring live external signal generators.
* **Historical Map Query:** `causal maps <trace> <event-id>` supports V3 and V4 traces containing virtual memory map metadata.

### 2. Header and Footer
Trace Format V4 maintains the standard fixed 16-byte header and 16-byte completion footer:
* **Header (16 bytes):**
  * Bytes `0..8`: Magic `b"CAUSAL\0\0"` (8 bytes)
  * Bytes `8..12`: `format_version = 4` (`u32` little-endian)
  * Bytes `12..14`: `architecture = 1` (`u16` little-endian, Linux x86-64)
  * Byte `14`: `byte_order = 1` (`u8`, little-endian)
  * Byte `15`: `pointer_width = 8` (`u8`, 64-bit)
* **Footer (16 bytes):**
  * Bytes `0..8`: `event_count` (`u64` little-endian)
  * Bytes `8..16`: Footer Magic `b"CAUSEND\0"` (8 bytes)

### 3. Wire Layout: SignalDelivery (Event Kind 7)
Every `SignalDelivery` record consists of a 4-byte framing length prefix (`160` bytes) followed by a 32-byte record header and 128 bytes of raw `siginfo_t`:

```text
+-------------------------------------------------------------------------+
| Length Prefix: 4 bytes (u32 LE = 160)                                   |
+-------------------------------------------------------------------------+
| Body Offset | Size | Type   | Field Name     | Description              |
|-------------+------+--------+----------------+--------------------------|
| 0..1        | 1    | u8     | kind           | 7 (SignalDelivery)       |
| 1..4        | 3    | [u8;3] | reserved       | [0, 0, 0]                |
| 4..12       | 8    | u64    | event_id       | Monotonic event sequence |
| 12..16      | 4    | u32    | tid            | Thread / Process ID      |
| 16..20      | 4    | i32    | signal_number  | Signal number (1..64)    |
| 20..24      | 4    | i32    | si_errno       | Signal errno             |
| 24..28      | 4    | i32    | si_code        | Signal code (e.g. SI_USER|
| 28..32      | 4    | u32    | siginfo_len    | Exactly 128              |
| 32..160     | 128  | [u8]   | siginfo_bytes  | Linux x86-64 siginfo_t   |
+-------------------------------------------------------------------------+
```
Total on-wire footprint per `SignalDelivery` event is **164 bytes**.

### 4. Siginfo ABI Policy & Deterministic Zero-Initialization
* **Fixed Size Policy:** On Linux x86-64, `sizeof(siginfo_t)` is 128 bytes (`SI_MAX_SIZE = 128`).
* **Zero-Initialization:** Unused padding bytes in `siginfo_t` are zero-initialized prior to recording and serialization to ensure bit-for-bit reproducible byte streams across runs.
* **Field Verification:** Parsers verify that `si_signo`, `si_errno`, and `si_code` in the raw 128-byte block match the explicit fields in the 32-byte record header.

### 5. Recording-Side Stop Classification
When `waitpid` returns a stopped status that is not a syscall stop (`WSTOPSIG(status) != (SIGTRAP | 0x80)`):
1. CAUSAL queries the kernel using `ptrace(PTRACE_GETSIGINFO, pid, 0, &info)`.
2. **Supported Deterministic Signals:** Signals originating from `kill`, `tkill`, `tgkill`, or `raise` with `si_code == SI_USER` (0) or `si_code == SI_TKILL` (-6) (and non-group-stopping signal numbers) are classified as supported `SignalDelivery` events, written to the V4 trace, and reinjected with `ptrace(PTRACE_SYSCALL, pid, 0, signal_number)`.
3. **Plain SIGTRAP Distinction:** `raise(SIGTRAP)` generates a signal stop with `si_signo = 5` and `si_code = SI_TKILL`. CAUSAL records this as `SignalDelivery(SIGTRAP)` rather than misidentifying it as a ptrace breakpoint trap.
4. **Unsupported Classes:**
   * **Stopping Signals / Group-Stops:** `SIGKILL`, `SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`, `SIGCONT` are outside M6 scope.
   * **Synchronous Hardware Faults:** `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL` with `si_code > 0` are outside M6 deterministic replay.
   * Unsupported signals are cleanly rejected with an informative error, child processes are reaped, and partial traces are immediately removed from the filesystem.

### 6. Replay-Side tgkill Signal Synthesis and Siginfo Restoration
Replaying a signal delivery without live external senders requires active signal synthesis:
1. **The Ptrace Limitation:** Resuming a stopped tracee with `ptrace(PTRACE_SYSCALL, pid, 0, sig)` only delivers a signal if the tracee already has that signal pending in its kernel signal queue. It cannot synthesize custom `siginfo_t` metadata (like original `si_pid` or `si_uid`) from nothing.
2. **Deterministic `tgkill` Arming:**
   * While the tracee is stopped at the event preceding `SignalDelivery`, CAUSAL inspects the next trace event.
   * If the next event is `SignalDelivery`, CAUSAL calls `libc::tgkill(pid, pid, signal_number)` before resuming the tracee.
   * This places the signal into the tracee's pending signal queue without advancing the trace cursor.
3. **Signal Stop Handling & `PTRACE_SETSIGINFO`:**
   * The tracee immediately encounters a live signal-delivery stop for `signal_number`.
   * CAUSAL intercepts the stop, overwrites the kernel-generated `siginfo_t` using `ptrace(PTRACE_SETSIGINFO, pid, 0, &restored_info)`, and verifies the restoration with `PTRACE_GETSIGINFO`.
   * This guarantees that target `SA_SIGINFO` handlers receive the exact recorded `si_pid`, `si_uid`, and `si_code`.
   * CAUSAL consumes the `SignalDelivery` event, advances the cursor, and resumes the tracee with `ptrace(PTRACE_SYSCALL, pid, 0, signal_number)`.

### 7. Process Termination by Delivered Signal
If a recorded signal causes default process termination (e.g. unhandled `SIGTERM`), the child terminates with `WIFSIGNALED(status)`.
* CAUSAL accepts this termination if all trace events leading up to and including the signal delivery have been matched.
* The recording loop writes a valid completion footer before exiting.
* Replay completes with `TraceeTermination::Signaled(sig)`, resulting in a CLI exit code of `128 + sig` (e.g. 143 for SIGTERM).

---

## Known Limitations and Non-Goals
1. **Instruction-Exact Async Timing:** M6 reproduces logical signal delivery ordering relative to syscall boundaries; it does not simulate cycle-accurate asynchronous instruction interrupts.
2. **Signal Frame / ucontext Restoration:** M6 restores `siginfo_t` metadata for signal handlers. It does not rewrite or fake the machine register context passed in `ucontext_t` / `mcontext_t`.
3. **Group-Stop and Job Control:** Job control stop signals (`SIGSTOP`, `SIGTSTP`, etc.) and `SIGCONT` are not part of M6 deterministic replay.
4. **Synchronous Hardware Faults:** Replay of synchronous memory faults (`SIGSEGV`) requires full dirty-memory reconstruction and is deferred to future memory milestones.
