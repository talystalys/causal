# Milestone M4 Verification Report

## Environment

* **OS:** Linux
* **Kernel Version:** `6.18.43_1 #1 SMP PREEMPT_DYNAMIC Sat Aug 8 00:50:08 UTC 2026`
* **Architecture:** `x86_64`
* **Rust Compiler:** `rustc 1.97.1 (8bab26f4f 2026-07-14) (Void Linux)`
* **Cargo:** `cargo 1.97.0`
* **C Compiler:** `cc (GCC) 14.2.1 20250405`
* **Yama ptrace scope:** `1`

---

## Pre-Edit M3 Audit

Before editing, all M0, M1, M2, and M3 integration tests were executed against the accepted baseline:
```text
$ cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
test result: ok. 7 passed; 0 failed (m0_lifecycle)
test result: ok. 6 passed; 0 failed (m1_syscalls)
test result: ok. 21 passed; 0 failed (m2_trace)
test result: ok. 6 passed; 0 failed (m3_replay)
Total: 40 passed, 0 failed
```

---

## Primary-Source Read/Memory-Transfer Reconnaissance

Primary Linux sources inspected:
1. `arch/x86/entry/syscalls/syscall_64.tbl` (`0 common read sys_read`)
2. `fs/read_write.c` (`ksys_read`, `vfs_read`)
3. `mm/process_vm_access.c` (`process_vm_readv`, `process_vm_writev`)
4. Linux `man 2 read`, `man 2 process_vm_readv`, `man 2 process_vm_writev`
5. Rust `libc` crate bindings (`libc::process_vm_readv`, `libc::process_vm_writev`, `libc::iovec`)

### Authoritative Conclusions Used:
1. `SYS_read` is syscall number `0` on Linux x86-64.
2. `read(fd, buf, count)` populates at most `result` bytes into `buf` when `result > 0`.
3. Short reads (`0 < result < count`) are standard behavior and only `result` bytes are modified by the kernel.
4. `read()` returning `0` represents EOF or 0 bytes transferred; buffer memory remains untouched.
5. A negative result represents error and no memory payload is written.
6. `process_vm_readv(pid, local_iov, 1, remote_iov, 1, 0)` directly copies remote memory into CAUSAL's address space without modifying the remote process.
7. `process_vm_writev(pid, local_iov, 1, remote_iov, 1, 0)` directly copies recorded payload bytes into the remote process's address space.
8. Exact return value verification (`returned_len == expected_len`) guarantees complete transfer before resuming execution.

---

## Trace Format V2

* Advances `format_version` to `2` in the 16-byte fixed header (`CAUSAL\0\0`, version `2`, x86-64, little-endian, 64-bit).
* Introduces `KernelMemoryWrite` (`event_kind = 3`) with wire layout:
  * 4-byte record length prefix (`40 + data_len`).
  * 40-byte fixed event header (`kind=3`, `reserved=[0; 3]`, `event_id`, `tid`, `source_event_id`, `recorded_address`, `data_len`, `payload_reserved=0`).
  * `data_len` payload data bytes.
* Retains unchanged layouts for `SyscallEnter` (`kind=1`, 72-byte body) and `SyscallExit` (`kind=2`, 32-byte body).

---

## V1 Compatibility

* V1 traces remain fully parseable and dumpable.
* V1 getpid substitution replay continues to operate.
* V1 traces containing positive `SYS_read` exits are rejected during pre-launch validation with:
  `"V1 trace cannot replay SYS_read memory output; record again with Trace Format V2"`.

---

## Record-Time Memory Capture

* In `src/tracer.rs`, at `SYS_read` (`nr=0`) `EXIT` stop:
  * `SyscallExit` event is written.
  * If `result > 0`: `read_process_memory_exact(pid, buf_addr, result)` copies exactly `result` bytes from stopped tracee memory using `process_vm_readv`.
  * `KernelMemoryWrite` event is written immediately following the exit event.
  * If `result <= 0`: no memory event is written.

---

## Replay-Time Memory Injection

* In `src/replay.rs`, at `SYS_read` (`nr=0`) `ENTRY` stop:
  * Compares live requested count with recorded count (`live_entry.args[2] == rec_args[2]`).
  * Captures live buffer pointer (`live_buffer_address = live_entry.args[1]`).
  * Suppresses live `SYS_read` via `orig_rax = u64::MAX` (-1).
* At `SYS_read` `EXIT` stop:
  * Verifies suppression sentinel: `exit.sval == -38` (`-ENOSYS`).
  * If `result > 0`:
    * Consumes `KernelMemoryWrite` event.
    * Calls `write_process_memory_exact(pid, live_buffer_address, data)` via `process_vm_writev`.
    * Injects recorded result into native `RAX`.
  * If `result <= 0`:
    * Injects recorded result into native `RAX` with 0 memory mutations.

---

## Positive Short-Read Proof

Using [`read_replay.c`](file:///home/taly/proj/tests/fixtures/read_replay.c):
* Requested buffer count: `64` bytes.
* Input file content: `"CAUSAL_M4_PAYLOAD_18B"` (`21` bytes).
* Recorded result: `21` bytes.
* Captured `KernelMemoryWrite` length: `21` bytes.
* Unread buffer region (`buf[21..64]`) verified to preserve initialization sentinel `0xA5`.

---

## Deleted-Source Proof

1. Recorded `read_replay` on temporary file `/tmp/m4_input` (containing 21 bytes).
2. Deleted `/tmp/m4_input`.
3. Native execution of `./tests/bin/read_replay /tmp/m4_input`:
   * Exited with code `42` (negative control failed).
4. Replay under CAUSAL: `./target/debug/causal replay /tmp/m4_read.causal ./tests/bin/read_replay /tmp/m4_input`:
   * Diagnostic: `replay-memory event=62 syscall=read recorded_addr=0x7ffd701f5250 live_addr=0x7ffd6aebd930 len=21 suppressed=-38 injected_result=21`
   * Exited with code `0`.

---

## Modified-Source Proof

1. Overwrote `/tmp/m4_input` with corrupted bytes `"CORRUPTED_WRONG_DATA_BYTES_HERE"`.
2. Native execution failed with exit code `42`.
3. Replay under CAUSAL exited with code `0` (reproducing original recorded payload).

---

## EOF Proof

1. Recorded [`read_eof.c`](file:///home/taly/proj/tests/fixtures/read_eof.c) on an empty file (result `0`, no memory write event).
2. Added data to the file.
3. Native execution failed with exit code `42`.
4. Replay under CAUSAL exited with code `0` (suppressed live read, injected `RAX=0`, buffer remained untouched sentinel `0x5A`).

---

## Zero-Byte Proof

1. Executed [`read_zero_count.c`](file:///home/taly/proj/tests/fixtures/read_zero_count.c) (`count = 0`).
2. Trace recorded `result = 0` with no memory write event.
3. Replay under CAUSAL injected `RAX=0` and verified buffer sentinel `0x3C` remained untouched, exiting `0`.

---

## Failed-Read Proof

1. Executed [`read_failed.c`](file:///home/taly/proj/tests/fixtures/read_failed.c) (`fd = -1`).
2. Trace recorded `result = -9` (`-EBADF`) with no memory write event.
3. Replay under CAUSAL suppressed live read and injected `-9` into `RAX`, reproducing `errno == EBADF` in userspace with exit `0`.

---

## Live-vs-Recorded Address Handling

* Recorded address: `0x7ffd701f5250` (from record-time trace).
* Live replay buffer address: `0x7ffd6aebd930` (from live replay ptrace entry `args[1]`).
* Memory write destination passed to `process_vm_writev` was `0x7ffd6aebd930`.

---

## Binary Layout Evidence

Manual decode of raw bytes from `/tmp/m4_read.causal` via `hexdump -C`:
* Header (`0x00000000`): `43 41 55 53 41 4c 00 00 02 00 00 00 01 00 01 08` (`CAUSAL\0\0`, version `2`, arch `1`, LE, 64-bit pointer).
* Event record at `0x0000109c`:
  * Length prefix: `3d 00 00 00` (61 bytes = 40-byte header + 21 bytes payload).
  * `event_kind`: `03` (`KernelMemoryWrite`).
  * `reserved`: `00 00 00`.
  * `event_id`: `3e 00 00 00 00 00 00 00` (62).
  * `tid`: `26 49 00 00` (18726).
  * `source_event_id`: `3d 00 00 00 00 00 00 00` (61, matching preceding `SyscallExit`).
  * `recorded_address`: `50 52 1f 70 fd 7f 00 00` (`0x7ffd701f5250`).
  * `data_len`: `15 00 00 00` (21).
  * `payload_reserved`: `00 00 00 00` (0).
  * Payload data (`0x000010c8..10dc`): `43 41 55 53 41 4c 5f 4d 34 5f 50 41 59 4c 4f 41 44 5f 31 38 42` (`"CAUSAL_M4_PAYLOAD_18B"`).
* Footer (`0x00001199`): `41 00 00 00 00 00 00 00 43 41 55 53 45 4e 44 00` (count `65`, `CAUSEND\0`).

---

## Corruption Testing

Focused corruption tests verified:
1. `KernelMemoryWrite` in V1 -> rejected with descriptive error.
2. Unknown V2 event kind -> rejected.
3. Record length < 40 -> rejected.
4. Record length / data_len mismatch -> rejected.
5. Nonzero payload_reserved -> rejected.
6. `source_event_id` not matching preceding exit -> rejected.
7. `data_len` != read result -> rejected.
8. `recorded_address` != enter buffer address -> rejected.
9. Positive read missing memory write -> rejected.
10. Truncated payload -> rejected.

---

## Regression & Test Results

```text
$ cargo fmt --check
$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.13s

$ cargo test
     Running tests/integration/m0_lifecycle.rs (7 tests)   -> ok (7 passed)
     Running tests/integration/m1_syscalls.rs (6 tests)    -> ok (6 passed)
     Running tests/integration/m2_trace.rs (21 tests)      -> ok (21 passed)
     Running tests/integration/m3_replay.rs (6 tests)      -> ok (6 passed)
     Running tests/integration/m4_read_replay.rs (9 tests) -> ok (9 passed)
Total: 49 passed, 0 failed
```

---

## 100-Replay Stress Result

100 repeated replay runs of a single recorded positive `SYS_read` trace against a corrupted external file:
* **Outcome:** 100/100 successful iterations in under 1.5 seconds.
* Every run performed live `SYS_read` suppression, verified `-ENOSYS`, injected 21 bytes into the live buffer, injected `RAX=21`, and exited `0`.

---

## Acceptance Results

| Criterion | Description | Status |
| :--- | :--- | :--- |
| **A** | Pre-edit M0/M1/M2/M3 baseline passes | **PASS** |
| **B** | Repository HEAD/state matches accepted foundation | **PASS** |
| **C** | Primary-source `read()` semantics documented | **PASS** |
| **D** | Primary-source `process_vm_readv/writev` semantics documented | **PASS** |
| **E** | Native x86-64 `SYS_read` identified correctly (`nr=0`) | **PASS** |
| **F** | Trace Format V1 wire semantics not silently modified | **PASS** |
| **G** | Trace Format V2 exists with explicit version `2` | **PASS** |
| **H** | V1 traces remain parseable | **PASS** |
| **I** | V2 traces are parseable | **PASS** |
| **J** | Production `record -o` produces V2 | **PASS** |
| **K** | V1 SyscallEnter layout remains unchanged | **PASS** |
| **L** | V1 SyscallExit layout remains unchanged | **PASS** |
| **M** | V2 kind 1/2 layouts remain compatible with V1 | **PASS** |
| **N** | V2 event kind 3 is `KernelMemoryWrite` | **PASS** |
| **O** | KernelMemoryWrite wire layout matches ADR exactly | **PASS** |
| **P** | V1 rejects event kind 3 | **PASS** |
| **Q** | V2 rejects unknown event kinds | **PASS** |
| **R** | V2 memory-event record length is validated | **PASS** |
| **S** | V2 memory-event `data_len` is validated | **PASS** |
| **T** | V2 memory-event reserved fields are validated | **PASS** |
| **U** | KernelMemoryWrite source_event_id references correct exit | **PASS** |
| **V** | KernelMemoryWrite source must be positive `SYS_read` | **PASS** |
| **W** | KernelMemoryWrite data length equals source read result | **PASS** |
| **X** | KernelMemoryWrite recorded address equals read-enter buffer address | **PASS** |
| **Y** | Positive read without required memory event is rejected | **PASS** |
| **Z** | Zero/negative read with inappropriate memory event is rejected | **PASS** |
| **AA** | Synthetic V2 serialization is deterministic byte-for-byte | **PASS** |
| **AB** | Independent hexdump confirms V2 byte layout | **PASS** |
| **AC** | Recorder captures read memory at syscall EXIT, not ENTRY | **PASS** |
| **AD** | Recorder captures exactly `result` bytes | **PASS** |
| **AE** | Recorder never captures full requested count when result is shorter | **PASS** |
| **AF** | Recorder uses `process_vm_readv` | **PASS** |
| **AG** | Recorder requires exact remote-memory transfer | **PASS** |
| **AH** | Failed/partial capture makes recording fail | **PASS** |
| **AI** | Replay uses `process_vm_writev` | **PASS** |
| **AJ** | Replay requires exact remote-memory write length | **PASS** |
| **AK** | Replay uses LIVE buffer address | **PASS** |
| **AL** | Replay never uses recorded_address as injection destination | **PASS** |
| **AM** | Replay compares live read count with recorded read count | **PASS** |
| **AN** | Replay does not require live buffer pointer equality | **PASS** |
| **AO** | Replay does not require live fd equality | **PASS** |
| **AP** | Live `SYS_read` is suppressed | **PASS** |
| **AQ** | Read suppression is verified via pre-injection `-ENOSYS` | **PASS** |
| **AR** | Positive recorded bytes injected before userspace resumes | **PASS** |
| **AS** | Positive recorded result injected into RAX | **PASS** |
| **AT** | Memory injection occurs before success result injection/resume | **PASS** |
| **AU** | Short-read result is reproduced | **PASS** |
| **AV** | Short-read bytes are reproduced | **PASS** |
| **AW** | Bytes beyond short-read result remain unchanged in sentinel region | **PASS** |
| **AX** | Deleted-source native negative control fails | **PASS** |
| **AY** | Deleted-source replay succeeds using recorded bytes | **PASS** |
| **AZ** | Modified-source native control fails | **PASS** |
| **BA** | Modified-source replay succeeds using original recorded bytes | **PASS** |
| **BB** | EOF result 0 is recorded with no memory event | **PASS** |
| **BC** | EOF replay suppresses live read and injects 0 | **PASS** |
| **BD** | EOF replay performs no memory write | **PASS** |
| **BE** | Zero-byte read replayed with result 0 and no memory mutation | **PASS** |
| **BF** | Failed read stores no memory payload | **PASS** |
| **BG** | Failed read replay injects recorded negative result | **PASS** |
| **BH** | Failed read replay behaviorally reproduces expected error | **PASS** |
| **BI** | V2 replay operates without getpid when read is substitution | **PASS** |
| **BJ** | M3 getpid substitution still works | **PASS** |
| **BK** | V2 trace replays both read and getpid substitutions in one stream | **PASS** |
| **BL** | Replay strictly matches event phase and syscall number | **PASS** |
| **BM** | Malformed V2 trace rejected before target launch | **PASS** |
| **BN** | V1 positive-read replay fails explicitly | **PASS** |
| **BO** | Replay source trace remains unchanged | **PASS** |
| **BP** | Replay divergence kills/reaps tracee | **PASS** |
| **BQ** | No test leaves stopped/zombie child | **PASS** |
| **BR** | All M0 tests pass | **PASS** |
| **BS** | All M1 tests pass | **PASS** |
| **BT** | All M2 tests pass (unsupported-version test evolved) | **PASS** |
| **BU** | All M3 tests pass (no-substitutions test evolved) | **PASS** |
| **BV** | All M4 tests pass | **PASS** |
| **BW** | 100-run positive-read replay stress succeeds against changed file | **PASS** |
| **BX** | No test hangs | **PASS** |
| **BY** | No test panics | **PASS** |
| **BZ** | `cargo fmt --check` passes | **PASS** |
| **CA** | `cargo clippy --all-targets -- -D warnings` passes | **PASS** |
| **CB** | `cargo test` passes (49/49 tests) | **PASS** |
| **CC** | ADR 0003 exists and matches implementation | **PASS** |
| **CD** | M4 verification report contains actual evidence | **PASS** |
| **CE** | CURRENT_STATUS.md accurately says M4 PASS | **PASS** |
| **CF** | README.md remains absent | **PASS** |
| **CG** | No M5 memory-map model implemented | **PASS** |
| **CH** | No full deterministic replay claim is made | **PASS** |
| **CI** | Git commit author is `talystalys <cosmolel04@gmail.com>` | **PASS** |
| **CJ** | Final local M4 commit created automatically after verification | **PASS** |

## Verification Closure

This section documents the execution evidence addressing the verification gaps:

### 1. Mixed SYS_getpid and SYS_read Replay (Criterion BK)
Using [`tests/fixtures/mixed_replay.c`](file:///home/taly/proj/tests/fixtures/mixed_replay.c):
* Record-time trace (`/tmp/m4_mixed.causal`) captured both substitutions:
  * `Event 58`: `SyscallEnter(nr=39)` -> `Event 59`: `SyscallExit(nr=39, result=30605)`
  * `Event 62`: `SyscallEnter(nr=0, count=64)` -> `Event 63`: `SyscallExit(nr=0, result=21)` -> `Event 64`: `KernelMemoryWrite(source=63, addr=0x7ffe5578d460, len=21)`
* Deleted external source file `/tmp/m4_mixed_input.txt`.
* Native negative control (`CAUSAL_EXPECT_GETPID=30605 ./tests/bin/mixed_replay /tmp/m4_mixed_input.txt`): exited with status `42`.
* CAUSAL replay (`CAUSAL_EXPECT_GETPID=30605 causal replay /tmp/m4_mixed.causal ./tests/bin/mixed_replay /tmp/m4_mixed_input.txt`):
  * Emitted diagnostics:
    ```text
    replay-substitute event=59 syscall=getpid recorded=30605 live_pid=30610 suppressed=-38 injected=30605
    replay-memory event=64 syscall=read recorded_addr=0x7ffe5578d460 live_addr=0x7fffcb8420f0 len=21 suppressed=-38 injected_result=21
    ```
  * Exited with code `0`. Both getpid and read substitutions succeeded within the same replay execution.

### 2. Remote Memory Transfer Failure and Exactness (Criteria AH & AJ)
Exercised in `test_m4_remote_memory_transfer_failure_exactness` against a controlled stopped child process (`pid`):
* `read_process_memory_exact(pid, 0x0, 64)` attempted remote memory read on unmapped address `0x0`:
  * Returned `Err("process_vm_readv failed for pid ...: Bad address (os error 14)")`.
  * Verified helper rejects non-exact/failed transfer without false success.
* `write_process_memory_exact(pid, 0x0, b"test_payload")` attempted remote memory write on unmapped address `0x0`:
  * Returned `Err("process_vm_writev failed for pid ...: Bad address (os error 14)")`.
  * Verified helper rejects non-exact/failed transfer without false success.

### 3. V2 Relational Corruption Cases (Criteria Z, C1, C2, C3, C4)
Exercised in `test_m4_v2_corruption_cases`:
* **C1 (`source_event_id` references `SyscallEnter`):**
  * Synthetic trace with `KernelMemoryWrite` pointing to `SyscallEnter` ID.
  * Rejected: `Err("trace event 2: KernelMemoryWrite source_event_id 1 points to a SyscallEnter, expected SyscallExit")`.
* **C2 (`source_event_id` references non-read `SyscallExit`):**
  * Synthetic trace with `KernelMemoryWrite` pointing to `SyscallExit` for `SYS_write` (`nr=1`).
  * Rejected: `Err("trace event 3: KernelMemoryWrite attached to SyscallExit nr=1, expected SYS_read (0)")`.
* **C3 / Z (`KernelMemoryWrite` attached to zero-result `SYS_read`):**
  * Synthetic trace with `KernelMemoryWrite` following `SyscallExit(nr=0, result=0)`.
  * Rejected: `Err("trace event 3: KernelMemoryWrite attached to zero-result read exit event 2")`.
* **C4 / Z (`KernelMemoryWrite` attached to failed negative `SYS_read`):**
  * Synthetic trace with `KernelMemoryWrite` following `SyscallExit(nr=0, result=-9)`.
  * Rejected: `Err("trace event 3: KernelMemoryWrite attached to failed read exit event 2 (result=-9)")`.

---

## Known Limitations

* Linux x86-64 single-process, single-threaded native ELF targets only.
* Memory output substitution in M4 is strictly limited to `SYS_read` (`nr=0`).
* Replay does not reconstruct kernel file description offsets or broader file descriptor table state.
* Non-substituted syscalls continue to execute live against the host kernel.
* Signal delivery events and memory maps (`mmap`/`brk`) are not replayed in M4.

---

## Final Classification

**PASS**
