# ADR 0001: CAUSAL Trace Format Version 1 (V1)

## Status
Accepted

## Context
Milestone M1 established reliable live ptrace observation and classification of syscall entry and exit stops on Linux x86-64. Milestone M2 requires these observations to be persisted in an explicit, versioned, independently parseable binary format so that traces can be stored and inspected later (via `causal dump`) without requiring live execution.

Rust in-memory representation (`repr(Rust)`, enum layouts, struct padding, or `usize` widths) is **not** the file ABI. The format must be framed, bounded, unambiguous, and completely independent of the tracer's in-memory layout.

## Decision
We define and implement **CAUSAL Trace Format V1**, a compact, little-endian, framed binary wire format.

### 1. File Structure Overview
A complete and valid V1 trace file consists of three contiguous sections:
```text
+-------------------------------------------------------------+
| Header (16 bytes)                                           |
+-------------------------------------------------------------+
| Event Record 1 (Framed, variable size: 76 or 36 bytes)      |
| Event Record 2                                              |
| ...                                                         |
| Event Record N                                              |
+-------------------------------------------------------------+
| Completion Footer (16 bytes)                                |
+-------------------------------------------------------------+
```
There must be no trailing bytes after the footer.

---

### 2. Header Layout (16 bytes)

| Offset | Size (Bytes) | Field | Type | Encoded Value / Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `8` | `magic` | `[u8; 8]` | Fixed ASCII: `CAUSAL\0\0` (`0x43 0x41 0x55 0x53 0x41 0x4c 0x00 0x00`) |
| `8` | `4` | `format_version` | `u32` (LE) | `1` (Format Version 1) |
| `12` | `2` | `architecture` | `u16` (LE) | `1` (Linux x86-64) |
| `14` | `1` | `byte_order` | `u8` | `1` (Little-Endian) |
| `15` | `1` | `pointer_width` | `u8` | `8` (64-bit pointers) |

---

### 3. Event Record Framing

Every event record begins with a 4-byte length prefix specifying the size of the record body that immediately follows (excluding the length prefix itself).

| Offset in Record | Size (Bytes) | Field | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `4` | `record_length` | `u32` (LE) | Length of following record body (72 for Enter, 32 for Exit) |
| `4` | `1` | `event_kind` | `u8` | `1` = SyscallEnter, `2` = SyscallExit |
| `5` | `3` | `reserved` | `[u8; 3]` | Must be encoded as zero (`0x00 0x00 0x00`) |
| `8` | `8` | `event_id` | `u64` (LE) | Monotonically increasing ID starting at 1 (1, 2, 3, ...) |
| `16` | `4` | `tid` | `u32` (LE) | Thread/Process ID of tracee |
| `20` | `...` | `payload` | Specific | Event-specific payload (see below) |

---

### 4. Event Kind Definitions

#### Event Kind 1: `SyscallEnter` (`event_kind = 1`)
* **`record_length`:** `72` (`0x48 0x00 0x00 0x00`)
* **Total wire length:** `76` bytes (`4 + 72`)
* **Payload:**
  * `syscall_number` (`u64` LE, 8 bytes): Linux x86-64 syscall number.
  * `args` (`[u64; 6]` LE, 48 bytes): Raw 64-bit values for `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.

#### Event Kind 2: `SyscallExit` (`event_kind = 2`)
* **`record_length`:** `32` (`0x20 0x00 0x00 0x00`)
* **Total wire length:** `36` bytes (`4 + 32`)
* **Payload:**
  * `syscall_number` (`u64` LE, 8 bytes): Matching syscall number from the pending entry.
  * `result` (`i64` LE, 8 bytes): Signed return value (`rax`).

---

### 5. Completion Footer Layout (16 bytes)

A valid trace file must conclude with a completion footer certifying that the trace was cleanly finalized by CAUSAL.

| Offset in Footer | Size (Bytes) | Field | Type | Encoded Value / Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `8` | `event_count` | `u64` (LE) | Total number of event records in the trace file |
| `8` | `8` | `footer_magic` | `[u8; 8]` | Fixed ASCII: `CAUSEND\0` (`0x43 0x41 0x55 0x53 0x45 0x4e 0x44 0x00`) |

---

### 6. Validation Rules for Readers
1. **Header Validation:** File size must be $\ge 32$ bytes. Magic must equal `CAUSAL\0\0`. V1 readers reject unknown format versions (`format_version != 1`) rather than guessing. Unsupported architectures (`!= 1`), byte orders (`!= 1`), or pointer widths (`!= 8`) are rejected.
2. **Framing & Length Validation:** `record_length` must strictly equal `72` for `SyscallEnter` and `32` for `SyscallExit`. Unknown event kinds are rejected.
3. **Monotonicity:** `event_id` must start at `1` and increment by exactly `1` for each successive event.
4. **Footer Validation:** The final 16 bytes must contain the valid `CAUSEND\0` magic, and `event_count` must equal the number of parsed event records.
5. **No Trailing Data:** EOF must occur immediately following the footer.

---

## Known Limitations & Future Compatibility Policy
* V1 supports single-process, single-threaded Linux x86-64 native ELF targets.
* Raw register values are stored; userspace memory payloads (e.g. string/buffer contents) are not dereferenced or captured in V1.
* When future breaking trace format versions are introduced, CAUSAL will either implement explicit format migration or reject incompatible versions with a descriptive error.
