# ADR 0003: Trace Format V2 and Kernel Memory Output Event Specification

## Status
Accepted

## Context
Trace Format V1 (defined in ADR 0001) established persistent binary recording for syscall entry and exit events (`SyscallEnter` and `SyscallExit`). V1 captures execution flow and register results, enabling deterministic register substitution such as `SYS_getpid` in Milestone M3.

Milestone M4 introduces memory-output replay for `SYS_read`. For a successful positive `read(fd, buf, count)` returning $N > 0$ bytes, the kernel mutates both the return register (`RAX = N`) and tracee memory at `buf[0..N]`. To reproduce this syscall deterministically during replay without accessing the original external source, CAUSAL must capture the exact $N$ bytes at record time and store them persistently in the trace.

### Why V1 Cannot Be Silently Extended
In Trace Format V1, `format_version` was set to `1`, and event kinds were restricted to `1` (`SyscallEnter`) and `2` (`SyscallExit`). Adding a new memory event kind to `format_version = 1` would silently mutate the wire semantics of V1 and violate decoder guarantees. Therefore, we advance the format version to `2` (Trace Format V2) while preserving complete backward compatibility for reading V1 traces.

---

## Decision

We introduce **CAUSAL Trace Format V2** featuring a new event kind: `KernelMemoryWrite` (`event_kind = 3`).

### 1. Compatibility Policy
* **V1 Reader Compatibility:** Preserved. Existing V1 traces remain parseable and inspectable via `causal dump`.
* **V2 Reader Support:** Added. Decodes event kinds 1, 2, and 3.
* **Production Recording:** `causal record -o ...` produces Trace Format V2 files by default.
* **V1 Replay Compatibility:** V1 traces containing `SYS_getpid` substitutions continue to replay correctly. If a V1 trace containing a positive `SYS_read` is replayed, CAUSAL rejects it with an explicit diagnostic (`"V1 trace cannot replay SYS_read memory output; record again with Trace Format V2"`) rather than pretending determinism.

### 2. Header and Footer
Trace Format V2 retains the identical 16-byte fixed header and 16-byte completion footer:
* **Header (16 bytes):**
  * Bytes `0..8`: Magic `b"CAUSAL\0\0"` (8 bytes)
  * Bytes `8..12`: `format_version = 2` (`u32` little-endian)
  * Bytes `12..14`: `architecture = 1` (`u16` little-endian, Linux x86-64)
  * Byte `14`: `byte_order = 1` (`u8`, little-endian)
  * Byte `15`: `pointer_width = 8` (`u8`, 64-bit)
* **Footer (16 bytes):**
  * Bytes `0..8`: `event_count` (`u64` little-endian)
  * Bytes `8..16`: Footer Magic `b"CAUSEND\0"` (8 bytes)

### 3. Event Kinds in V2
* `event_kind = 1`: `SyscallEnter` (record length = 72 bytes, wire size = 76 bytes)
* `event_kind = 2`: `SyscallExit` (record length = 32 bytes, wire size = 36 bytes)
* `event_kind = 3`: `KernelMemoryWrite` (record length = 40 + `data_len` bytes, wire size = 44 + `data_len` bytes)

### 4. KernelMemoryWrite Wire Layout
Each `KernelMemoryWrite` record begins with a 4-byte little-endian record length prefix (`record_length = 40 + data_len`), followed by the event body:

| Offset in Body | Size (bytes) | Type | Field Name | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `1` | `u8` | `event_kind` | Must be `3` |
| `1` | `3` | `[u8; 3]` | `reserved` | Reserved, must be `0` |
| `4` | `8` | `u64` | `event_id` | Monotonically increasing global event ID |
| `12` | `4` | `u32` | `tid` | Thread ID that received the memory write |
| `16` | `8` | `u64` | `source_event_id` | Event ID of the immediately preceding `SyscallExit` |
| `24` | `8` | `u64` | `recorded_address` | Record-time memory buffer address (`args[1]` of entry) |
| `32` | `4` | `u32` | `data_len` | Number of payload bytes written by kernel ($N$) |
| `36` | `4` | `u32` | `payload_reserved`| Reserved, must be `0` |
| `40` | `N` | `[u8; N]` | `data` | The exact $N$ bytes written into tracee memory |

### 5. Semantic Invariants & Addressing Rules

#### Observational Metadata vs. Live Replay Destination
* `recorded_address` is observational metadata and is **never** used as the replay destination.
* Replay writes memory to the **live buffer pointer** captured from the replay syscall entry (`live_entry.args[1]`).
* This ensures replay remains fully functional across varying ASLR layouts and stack/heap placements.

#### Positive SYS_read Requirements ($N > 0$)
* A positive `SYS_read` must produce the exact sequence: `SyscallEnter(nr=0)` $\rightarrow$ `SyscallExit(nr=0, result=N)` $\rightarrow$ `KernelMemoryWrite(source_event_id=exit.id, len=N)`.
* `data_len` must exactly equal `result`.
* `data.len()` must exactly equal `data_len`.
* `recorded_address` must equal `SyscallEnter.args[1]`.
* `result` must be $\le$ `SyscallEnter.args[2]` (requested count).

#### Non-Positive SYS_read Rules ($N \le 0$)
* For EOF (`result = 0`), zero-byte reads (`count = 0`), or failed reads (`result < 0`), no `KernelMemoryWrite` event may be written.
* Replay suppresses the live syscall, validates `-ENOSYS`, injects the return value into `RAX`, and performs no memory mutation.

---

## Consequences & Limitations
* Enables deterministic replay of `SYS_read` even when external files are modified or deleted.
* Replay is currently scoped to single-threaded native Linux x86-64 ELF targets.
* Replay does not reconstruct kernel file-description offsets or broader external FD table state.
