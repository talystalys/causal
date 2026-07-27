# Milestone M2 Verification Report

## Environment

* **OS:** Linux
* **Kernel Version:** `6.18.43_1 #1 SMP PREEMPT_DYNAMIC Sat Aug 8 00:50:08 UTC 2026`
* **Architecture:** `x86_64`
* **Rust Compiler:** `rustc 1.97.1 (8bab26f4f 2026-07-14) (Void Linux)`
* **Cargo:** `cargo 1.97.0`
* **C Compiler:** `cc (GCC) 14.2.1 20250405`
* **strace Version:** `strace -- version 7.1`
* **Yama ptrace scope:** `1`

---

## M1 Baseline Confirmation

Prior to modifying code for M2, all M0 and M1 integration tests were run and passed:
```text
$ ./scripts/build-fixtures.sh && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
test result: ok. 7 passed; 0 failed (m0_lifecycle)
test result: ok. 6 passed; 0 failed (m1_syscalls)
```

---

## Format Specification Summary (Trace Format V1)

* **Header (16 bytes):**
  * Magic: `CAUSAL\0\0` (`0x43 0x41 0x55 0x53 0x41 0x4c 0x00 0x00`)
  * `format_version`: `1_u32` (little-endian)
  * `architecture`: `1_u16` (1 = Linux x86-64)
  * `byte_order`: `1_u8` (1 = little-endian)
  * `pointer_width`: `8_u8` (8 bytes = 64-bit)
* **Framed Event Records:**
  * `record_length`: `u32` (LE) length prefix (excluding the 4-byte prefix itself)
  * `event_kind`: `1` (SyscallEnter, `record_length=72`, total wire size=76 bytes) or `2` (SyscallExit, `record_length=32`, total wire size=36 bytes)
  * `reserved`: 3 zero bytes (`0x00 0x00 0x00`)
  * `event_id`: Monotonically increasing `u64` starting at `1`
  * `tid`: `u32` thread ID
  * Payload:
    * SyscallEnter: `syscall_number` (`u64`) + `args` (`[u64; 6]`)
    * SyscallExit: `syscall_number` (`u64`) + `result` (`i64`)
* **Completion Footer (16 bytes):**
  * `event_count`: `u64` (LE) total number of event records
  * Magic: `CAUSEND\0` (`0x43 0x41 0x55 0x53 0x45 0x4e 0x44 0x00`)

---

## Live Recording Execution

Command executed:
```bash
./target/debug/causal record -o /tmp/write_hello.causal ./tests/bin/write_hello
```
Live console output observed:
```text
syscall-enter tid=3593 nr=1 args=[1, 140734037785921, 6, 0, 140418041637808, 0]
hello
syscall-exit  tid=3593 nr=1 result=6
syscall-enter tid=3593 nr=231 args=[0, 18446744073709551496, 231, 140734037785488, 140734037785728, 0]
child exited with status 0
```

---

## Dump Evidence

Command executed:
```bash
./target/debug/causal dump /tmp/write_hello.causal
```
Dump output:
```text
000001 syscall-enter tid=3593 nr=12 args=[0, 5168, 0, 9, 140418041833264, 0]
000002 syscall-exit  tid=3593 nr=12 result=93946302164992
...
000057 syscall-enter tid=3593 nr=1 args=[1, 140734037785921, 6, 0, 140418041637808, 0]
000058 syscall-exit  tid=3593 nr=1 result=6
000059 syscall-enter tid=3593 nr=231 args=[0, 18446744073709551496, 231, 140734037785488, 140734037785728, 0]
```
Deliberate write verification in dump:
* `nr = 1` (`SYS_write`)
* `fd = 1` (`STDOUT_FILENO`)
* `count = 6`
* `result = 6`

---

## Binary Layout Inspection

Hexdump excerpt of `/tmp/write_hello.causal`:
```text
00000000  43 41 55 53 41 4c 00 00  01 00 00 00 01 00 01 08  |CAUSAL..........|
00000010  48 00 00 00 01 00 00 00  01 00 00 00 00 00 00 00  |H...............|
00000020  09 0e 00 00 0c 00 00 00  00 00 00 00 00 00 00 00  |................|
...
00000d00  ff 7f 00 00 00 00 00 00  00 00 00 00 3b 00 00 00  |............;...|
00000d10  00 00 00 00 43 41 55 53  45 4e 44 00              |....CAUSEND.|
```

### Manual Byte Decoding:
1. **Header (`0x00..0x10`):**
   * `43 41 55 53 41 4c 00 00`: Magic `CAUSAL\0\0`
   * `01 00 00 00`: Format Version `1` (`u32` LE)
   * `01 00`: Architecture `1` (Linux x86-64, `u16` LE)
   * `01`: Byte order `1` (Little-Endian)
   * `08`: Pointer width `8` bytes (64-bit)
2. **First Event Record (`0x10..0x5C`):**
   * `48 00 00 00`: `record_length = 72` (`u32` LE)
   * `01`: `event_kind = 1` (`SyscallEnter`)
   * `00 00 00`: 3 reserved bytes
   * `01 00 00 00 00 00 00 00`: `event_id = 1` (`u64` LE)
   * `09 0e 00 00`: `tid = 3593` (`u32` LE)
   * `0c 00 00 00 00 00 00 00`: `syscall_number = 12` (`SYS_brk`)
3. **Footer (`0x0D0C..0x0D1C`):**
   * `3b 00 00 00 00 00 00 00`: `event_count = 59` (`u64` LE)
   * `43 41 55 53 45 4e 44 00`: Magic `CAUSEND\0`

---

## Deterministic Codec Serialization

A synthetic stream with fixed event IDs, TIDs, syscall numbers, arguments, and return values was encoded across two separate runs. The resulting byte vectors were verified to be byte-for-byte identical.

*Note:* Real process executions naturally differ in memory buffer addresses due to ASLR and environment layouts; M2 serializes observations faithfully without assuming ASLR-affected trace files are byte-identical across runs.

---

## Corruption and Error Testing

| Case | Tested Condition | Outcome |
| :--- | :--- | :--- |
| **Bad Header Magic** | Header starts with `NOTMAGIC` | Rejected with `invalid trace header magic`, exit 1, no panic |
| **Unsupported Version** | Header specifies version `2` | Rejected with `unsupported trace format version 2`, exit 1 |
| **Unsupported Architecture** | Header specifies arch `2` | Rejected with `unsupported trace architecture id 2`, exit 1 |
| **Truncated Trace** | File cut short (< 32 bytes) | Rejected with `incomplete trace`, exit 1 |
| **Missing Footer** | Incomplete trace without footer | Rejected with `completion footer missing`, exit 1 |
| **Bad Footer Magic** | Footer magic altered | Rejected with `completion footer missing`, exit 1 |
| **Event Count Mismatch** | Footer count does not match parsed count | Rejected with `event count mismatch`, exit 1 |
| **Non-monotonic Event ID** | Duplicate or out-of-order event IDs | Rejected with `non-monotonic event id`, exit 1 |
| **Trailing Garbage** | Bytes appended after footer | Rejected with `completion footer missing`, exit 1 |
| **Launch Failure Cleanup** | Traced target fails `exec` | Incomplete trace file automatically deleted |

---

## Regression & Stress Results

* **Regression Test Suite:** 34/34 tests passed (`cargo test`):
  * `m0_lifecycle`: 7/7 passed
  * `m1_syscalls`: 6/6 passed
  * `m2_trace`: 21/21 passed
* **Stress Test:** 100 consecutive `record -o` and `dump` cycles completed cleanly under timeout protection with 0 failures or leaks.

---

## Acceptance Results

| Criterion | Description | Status |
| :--- | :--- | :--- |
| **A** | M0/M1 baseline passes before editing | **PASS** |
| **B** | `causal record -o <trace> <program>` works | **PASS** |
| **C** | Existing `causal record <program>` works without trace path | **PASS** |
| **D** | Trace header has specified magic `CAUSAL\0\0` | **PASS** |
| **E** | Trace version is explicitly encoded as V1 | **PASS** |
| **F** | Architecture metadata encoded and validated (1 = x86-64) | **PASS** |
| **G** | Endianness (1) and pointer width (8) encoded and validated | **PASS** |
| **H** | SyscallEnter events are persisted | **PASS** |
| **I** | SyscallExit events are persisted | **PASS** |
| **J** | Six syscall entry arguments survive round-trip exactly | **PASS** |
| **K** | Signed syscall results survive round-trip exactly | **PASS** |
| **L** | Event IDs begin at 1 and increment monotonically | **PASS** |
| **M** | Trace events written streaming during execution | **PASS** |
| **N** | Valid completion footer written only on clean completion | **PASS** |
| **O** | Footer event count matches persisted events | **PASS** |
| **P** | Missing footer is rejected | **PASS** |
| **Q** | Unsupported format version is rejected | **PASS** |
| **R** | Bad header magic is rejected | **PASS** |
| **S** | Unknown event kind is rejected | **PASS** |
| **T** | Malformed record length is rejected | **PASS** |
| **U** | Truncated records are rejected | **PASS** |
| **V** | Non-monotonic event IDs are rejected | **PASS** |
| **W** | Trailing garbage is rejected | **PASS** |
| **X** | `causal dump <trace>` prints valid trace | **PASS** |
| **Y** | Deliberate write dump contains correct `SYS_write`, `fd=1`, `count=6`, `result=6` | **PASS** |
| **Z** | Independent `hexdump` inspection confirms implemented binary layout | **PASS** |
| **AA** | Synthetic fixed event stream serializes byte-identically | **PASS** |
| **AB** | No real-execution byte-identical assumption across ASLR runs | **PASS** |
| **AC** | All existing M0 tests still pass | **PASS** |
| **AD** | All existing M1 tests still pass | **PASS** |
| **AE** | All M2 codec/integration tests pass | **PASS** |
| **AF** | 100 repeated record+dump runs pass | **PASS** |
| **AG** | No test hangs | **PASS** |
| **AH** | No test panics | **PASS** |
| **AI** | `cargo fmt --check` passes | **PASS** |
| **AJ** | `cargo clippy --all-targets -- -D warnings` passes | **PASS** |
| **AK** | `cargo test` passes (34/34 tests) | **PASS** |
| **AL** | Trace format ADR 0001 exists and matches implementation | **PASS** |
| **AM** | M2 verification report contains actual evidence | **PASS** |
| **AN** | `CURRENT_STATUS.md` is accurate | **PASS** |
| **AO** | No replay/M3 functionality implemented | **PASS** |

---

## Known Limitations

* Linux x86-64 single-process, single-threaded native ELF targets only.
* Raw register representation only (no userspace pointer dereferencing or syscall name database).
* Trace format is strictly Version 1.

---

## Final Classification

**PASS**
