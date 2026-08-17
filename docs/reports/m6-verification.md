# Milestone M6 Verification Report

## Environment

* **OS:** Linux
* **Kernel Version:** `6.18.43_1 #1 SMP PREEMPT_DYNAMIC Sat Aug 8 00:50:08 UTC 2026`
* **Architecture:** `x86_64`
* **Rust Compiler:** `rustc 1.97.1 (8bab26f4f 2026-07-14) (Void Linux)`
* **Cargo:** `cargo 1.97.0`
* **C Compiler:** `cc (GCC) 14.2.1 20250405`
* **Yama ptrace scope:** `1`

---

## Pre-Edit M5 Audit

Baseline verified at commit `7f1f6c2d88a2937d8605b9bb9858941b326bd4b0`:
```text
$ cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
test result: ok. 7 passed; 0 failed (m0_lifecycle)
test result: ok. 6 passed; 0 failed (m1_syscalls)
test result: ok. 21 passed; 0 failed (m2_trace)
test result: ok. 6 passed; 0 failed (m3_replay)
test result: ok. 11 passed; 0 failed (m4_read_replay)
test result: ok. 21 passed; 0 failed (m5_maps)
Total: 72 passed, 0 failed
```

---

## Primary-Source Signal/Ptrace Reconnaissance

1. **Ptrace Signal-Stop Mechanics:**
   * When a traced child encounters a signal-delivery stop, `waitpid` returns with `WIFSTOPPED(status)` where `WSTOPSIG(status) != (SIGTRAP | 0x80)`.
   * `PTRACE_GETSIGINFO` retrieves the pending `siginfo_t` associated with the signal delivery.
   * Resuming the child with `ptrace(PTRACE_SYSCALL, pid, 0, signal_number)` reinjects the signal to the child's handler or default disposition.
2. **Replay Signal Injection Challenge:**
   * Passing `signal_number` to `PTRACE_SYSCALL` during replay is insufficient if the signal is not pending in the kernel's queue, and does not allow restoring custom `siginfo_t` structures.
   * Synthesizing signals via `libc::tgkill(pid, pid, signal_number)` while the child is stopped at the preceding event forces a live signal-delivery stop.
   * `PTRACE_SETSIGINFO` overwrites the kernel-generated `siginfo_t` with recorded bytes, restoring sender PID, UID, and `si_code` before resuming.

---

## Trace Format V4 & SignalDelivery Wire Layout

Trace Format V4 introduces `EVENT_KIND_SIGNAL_DELIVERY = 7`:

* **Wire Framing:**
  * 4 bytes: Record length prefix (`u32` little-endian = 160)
  * 1 byte: `kind = 7`
  * 3 bytes: `reserved = [0, 0, 0]`
  * 8 bytes: `event_id` (`u64` little-endian)
  * 4 bytes: `tid` (`u32` little-endian)
  * 4 bytes: `signal_number` (`i32` little-endian, 1..64)
  * 4 bytes: `si_errno` (`i32` little-endian)
  * 4 bytes: `si_code` (`i32` little-endian)
  * 4 bytes: `siginfo_len` (`u32` little-endian = 128)
  * 128 bytes: Raw `siginfo_t` bytes matching Linux x86-64 ABI
* **Total wire footprint per event:** 164 bytes.
* **Deterministic Padding:** All uninitialized and padding bytes in `siginfo_t` are zero-initialized prior to recording, guaranteeing bit-for-bit serialization reproducibility.
* **ABI Size Verification:** Explicitly asserted via `test_m6_abi_size_proof` that `std::mem::size_of::<libc::siginfo_t>() == 128`.

---

## Signal-Stop Classification & PTRACE_GETSIGINFO

* **Supported Deterministic Signals:** Signals with `si_code == SI_USER` (0) or `si_code == SI_TKILL` (-6) (e.g. sent via `kill`, `tkill`, `tgkill`, `raise`) are classified as supported `SignalDelivery` events.
* **Plain SIGTRAP Distinction:** `raise(SIGTRAP)` generates a signal stop with `si_signo = 5` and `si_code = SI_TKILL`. CAUSAL records this as `SignalDelivery(SIGTRAP)` rather than misidentifying it as a ptrace breakpoint trap.
* **Unsupported Signals Rejection:**
  * Stopping signals / group-stops (`SIGKILL`, `SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`, `SIGCONT`) and synchronous hardware faults (`SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL`) are cleanly rejected with an informative error, child processes are killed and reaped, and partial traces are immediately removed from disk.

---

## External SIGUSR1 Recording & Replay Proof

1. **Flagship Recording:**
   * Test fixture `signal_external_usr1.c` registers an `SA_SIGINFO` handler and writes its PID to a readiness file before entering a busy loop.
   * External test harness reads the readiness file and issues `libc::kill(tracee_pid, SIGUSR1)`.
   * CAUSAL intercepts the non-syscall stop, captures `siginfo_t` via `PTRACE_GETSIGINFO`, writes `SignalDelivery(SIGUSR1, SI_USER, sender_pid)` to the V4 trace, and reinjects the signal.
   * Target handler receives the signal and verifies sender PID and code.
2. **Replay Proof (Zero External Senders):**
   * Target is executed under `causal replay` with **no external sender thread or signal**.
   * Replay engine arms `SIGUSR1` via `tgkill`, intercepts the live signal stop, restores recorded `siginfo_t` via `PTRACE_SETSIGINFO`, verifies restoration with `PTRACE_GETSIGINFO`, and reinjects the signal.
   * Full recorded siginfo buffer is supplied to `PTRACE_SETSIGINFO`; post-`GETSIGINFO` verifies common fields (`si_signo`, `si_code`, `si_errno`); target's `SA_SIGINFO` behavioral handler verifies recorded sender PID and code reach userspace, exiting 0.

---

## Default-Action SIGTERM Termination Proof

* Fixture `signal_external_term.c` has no signal handler.
* During recording, an external `SIGTERM` terminates the process. CAUSAL records `SignalDelivery(SIGTERM)`, captures child termination with `WTERMSIG == 15`, writes a valid completion footer, and exits with 143 (`128 + 15`).
* During replay with **no external sender**, CAUSAL synthesizes `SIGTERM`, restoring default termination. CLI exits with 143.

---

## Multi-Signal & Sycall Interleaving Proof

* **Multiple Signals:** Fixture `signal_multi_usr.c` delivers `SIGUSR1`, executes `getpid()`, and delivers `SIGUSR2`. CAUSAL records both signal delivery events and the intervening syscall, successfully replaying both in sequence.
* **Structural Pairing Invariance:** The V4 parser and structural validator accept `SignalDelivery` between syscall entry and exit stops while preserving pairing integrity (`SyscallEnter(X) -> SignalDelivery -> SyscallExit(X)`).

---

## M6 Correctness Closure Proofs

1. **Read Memory Write Adjacency Fix (Bug A Closure):**
   * Verified in `test_m6_bug_a_signal_breaks_read_memory_write_adjacency_rejected`.
   * A malformed trace sequence with a `SignalDelivery` event interposed between a positive `SYS_read` `SyscallExit` and its required `KernelMemoryWrite` event is strictly rejected by `validate_trace_structure` with `"SignalDelivery event ... interposes before required KernelMemoryWrite for positive SYS_read exit ..."`.
2. **Map Delta Adjacency Fix (Bug B Closure):**
   * Verified in `test_m6_bug_b_signal_breaks_map_delta_adjacency_rejected`.
   * In `validate_trace_structure`, `SignalDelivery` is recognized as an execution event that terminates map delta contiguity (`current_delta_group = None`, `last_syscall_exit_id = None`).
   * Traces with `SyscallExit(mmap) -> SignalDelivery -> MemoryMapAdd` or `SyscallExit(mprotect) -> MemoryMapRemove -> SignalDelivery -> MemoryMapAdd` are rejected with `"is not contiguous with triggering SyscallExit"`.
3. **Substituted Syscall Interposition Preflight Policy:**
   * Verified in `test_m6_replay_preflight_signal_interposed_in_substituted_syscall_rejected`.
   * Replaying a trace with a `SignalDelivery` interposed inside a substituted `SYS_getpid` or `SYS_read` pair is rejected before launching the target process with a clear diagnostic.
4. **Prelaunch Unsupported Signal Rejection:**
   * Verified in `test_m6_replay_preflight_unsupported_signal_rejected_prelaunch`.
   * Traces containing unsupported `si_code`s or stopping signals (`SIGSTOP`, `SIGKILL`, etc.) are validated and rejected prior to calling `launch_traced_child`.
5. **Comprehensive Parser-Level V4 Corruption Coverage:**
   * Verified in `test_m6_parser_level_corruption_cases` covering 15 synthetic corruption cases:
     * Raw kind 7 in V1, V2, and V3 files
     * `signal_number = 0` and `signal_number = 65`
     * Header truncation (< 32 bytes)
     * `siginfo_len` < 128 and > 128
     * Record length mismatch with `siginfo_len`
     * Truncated raw siginfo bytes
     * Raw `si_signo`, `si_errno`, and `si_code` mismatches
     * Unknown V4 event kind (kind 8)
     * `SignalDelivery` preceding initial `MemoryMapSnapshot`
6. **Watchdog Timeout & Cleanup Safety:**
   * All live signal tests (`signal_external_usr1`, `signal_external_term`, `100-replays stress`, `replay_divergence`) use bounded 5-second readiness polls and watchdog timers to prevent hanging tests or orphaned zombie processes.

---

## 100-Replay Signal Stress Test

* A single recorded external `SIGUSR1` trace was replayed **100 consecutive times** with zero external signals.
* **Result:** 100/100 successful replay runs (100% deterministic fidelity).

---

## Regression & Integration Test Summary

```text
$ cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
test result: ok. 7 passed; 0 failed (m0_lifecycle)
test result: ok. 6 passed; 0 failed (m1_syscalls)
test result: ok. 21 passed; 0 failed (m2_trace)
test result: ok. 6 passed; 0 failed (m3_replay)
test result: ok. 11 passed; 0 failed (m4_read_replay)
test result: ok. 21 passed; 0 failed (m5_maps)
test result: ok. 18 passed; 0 failed (m6_signals)
Total: 90 passed, 0 failed, 0 warnings
```

---

## Known Limitations and Non-Goals

1. **Instruction-Exact Async Timing:** Logical ordering at syscall/signal boundaries is preserved; cycle-accurate instruction counters are outside M6 scope.
2. **ucontext / Machine Register Frame Restoration:** `siginfo_t` metadata is restored; arbitrary machine register manipulation inside `ucontext_t` is not faked.
3. **Signal Interposition in Substituted Syscalls:** Interposed signals inside substituted `SYS_getpid` or `SYS_read` pairs are rejected preflight.
4. **Group-Stop & Job Control:** `SIGSTOP`, `SIGTSTP`, `SIGCONT` semantics are explicitly deferred.
5. **Synchronous Faults:** Replay of `SIGSEGV` is excluded from M6 deterministic replay.

---

## Final Classification

**PASS**
