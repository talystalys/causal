# ADR 0004: Virtual Memory-Map Model and Trace Format V3 Specification

## Status
Accepted

## Context
CAUSAL is a deterministic record/replay debugger specializing in asynchronous I/O. In future milestones (e.g. io_uring analysis), CAUSAL must explain and validate causal interactions between user buffers, kernel ring buffers, and asynchronous mutation events.

To understand address-space layout and validate memory accessibility across time without paying the prohibitive storage cost of capturing full memory snapshots on every operation, CAUSAL requires an authoritative, normalized model of the process virtual address space.

Milestone M5 introduces the process virtual memory-map model, tracking address-space topology across the lifecycle of the tracee using Linux `/proc/<pid>/maps`.

---

## Decision

We introduce **CAUSAL Trace Format V3** featuring three new event kinds:
1. `MemoryMapSnapshot` (`event_kind = 4`)
2. `MemoryMapAdd` (`event_kind = 5`)
3. `MemoryMapRemove` (`event_kind = 6`)

### 1. Compatibility Policy
* **V1 and V2 Reader Compatibility:** Preserved. Existing V1 and V2 traces remain fully parseable and inspectable via `causal dump`.
* **V3 Reader Support:** Added. Decodes event kinds 1 through 6.
* **Production Recording:** `causal record -o ...` produces Trace Format V3 files by default.
* **Replay Compatibility:** Deterministic replay of V1, V2, and V3 traces executes seamlessly. Replay skips map metadata events (`MemoryMapSnapshot`, `MemoryMapAdd`, `MemoryMapRemove`) and allows mapping syscalls (`mmap`, `mprotect`, `munmap`, `brk`) to execute live on the host kernel.
* **Historical Map Query:** `causal maps <trace> <event-id>` reconstructs VMA state from V3 traces. Querying a V1 or V2 trace is rejected with: `"causal: trace format V{} has no initial memory-map model; record again with V3"`.

### 2. Header and Footer
Trace Format V3 retains the standard 16-byte fixed header and 16-byte completion footer:
* **Header (16 bytes):**
  * Bytes `0..8`: Magic `b"CAUSAL\0\0"` (8 bytes)
  * Bytes `8..12`: `format_version = 3` (`u32` little-endian)
  * Bytes `12..14`: `architecture = 1` (`u16` little-endian, Linux x86-64)
  * Byte `14`: `byte_order = 1` (`u8`, little-endian)
  * Byte `15`: `pointer_width = 8` (`u8`, 64-bit)
* **Footer (16 bytes):**
  * Bytes `0..8`: `event_count` (`u64` little-endian)
  * Bytes `8..16`: Footer Magic `b"CAUSEND\0"` (8 bytes)

### 3. Event Kinds in V3
* `event_kind = 1`: `SyscallEnter` (record length = 72 bytes)
* `event_kind = 2`: `SyscallExit` (record length = 32 bytes)
* `event_kind = 3`: `KernelMemoryWrite` (record length = 40 + `data_len` bytes)
* `event_kind = 4`: `MemoryMapSnapshot` (record length = 24 + descriptor bytes)
* `event_kind = 5`: `MemoryMapAdd` (record length = 24 + descriptor bytes)
* `event_kind = 6`: `MemoryMapRemove` (record length = 24 + descriptor bytes)

### 4. Wire Formats

#### MemoryRegion Descriptor (48 + `label_len` bytes)
Every region descriptor begins with a 48-byte fixed binary prefix followed by variable label bytes:

| Offset | Size (bytes) | Type | Field Name | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0..8` | 8 | `u64` | `start` | Starting virtual address (4096-byte aligned) |
| `8..16` | 8 | `u64` | `end` | Ending virtual address (4096-byte aligned, > `start`) |
| `16..24` | 8 | `u64` | `file_offset` | File offset in bytes |
| `24..32` | 8 | `u64` | `inode` | Inode number |
| `32..36` | 4 | `u32` | `dev_major` | Device major ID |
| `36..40` | 4 | `u32` | `dev_minor` | Device minor ID |
| `40` | 1 | `u8` | `prot_bits` | Bitfield: bit 0 = read, bit 1 = write, bit 2 = exec |
| `41` | 1 | `u8` | `sharing` | `1` = private (`p`), `2` = shared (`s`) |
| `42..44` | 2 | `[u8; 2]` | `reserved` | Must be `0` |
| `44..48` | 4 | `u32` | `label_len` | Length of label in bytes |
| `48..` | `label_len` | `[u8]` | `label` | Descriptive pathname or mapping label |

#### MemoryMapSnapshot (kind = 4)
* Prefix: 4-byte little-endian record length (`24 + sum(descriptor_bytes)`).
* Body Header (16 bytes): `kind = 4`, `reserved = [0; 3]`, `event_id` (`u64`), `tid` (`u32`).
* Body Payload (8 bytes): `region_count` (`u32`), `reserved = 0` (`u32`).
* Descriptors: `region_count` packed `MemoryRegion` descriptors.

#### MemoryMapAdd (kind = 5) and MemoryMapRemove (kind = 6)
* Prefix: 4-byte little-endian record length (`24 + 48 + label_len`).
* Body Header (16 bytes): `kind = 5` or `6`, `reserved = [0; 3]`, `event_id` (`u64`), `tid` (`u32`).
* Body Payload (8 bytes): `source_event_id` (`u64`) referencing the triggering `SyscallExit`.
* Descriptor: 1 `MemoryRegion` descriptor.

### 5. Ground Truth and Recording Semantics
* **Ground Truth Source:** `/proc/<pid>/maps` is parsed while the tracee is stopped under ptrace.
* **Initial Bootstrap Snapshot:** Emitted at event 1 immediately upon post-`execve` bootstrap exit, prior to any userspace syscall entry.
* **Observed Mutation Syscalls:** `SYS_mmap` (9), `SYS_mprotect` (10), `SYS_munmap` (11), and `SYS_brk` (12).
* **Delta Computation & Invariants:**
  * When a mutation syscall completes at `SyscallExit`, a fresh map is read from `/proc/<pid>/maps`.
  * The model diff generates `MemoryMapRemove` for deleted/modified regions and `MemoryMapAdd` for newly created/modified regions.
  * For a given `source_event_id`, all `MemoryMapRemove` events are emitted first (sorted by `start` ascending), followed by all `MemoryMapAdd` events (sorted by `start` ascending).
  * Self-consistency is verified on every recording step: applying the deltas to a clone of the prior model must produce a state identical to the fresh `/proc/<pid>/maps`.
  * If a mapping syscall returns an error (`result < 0`), no map deltas may be emitted.

---

## Consequences & Verification
* Full temporal reconstruction of virtual memory state is possible at any event ID via `causal maps`.
* Memory topology is decoupled from memory contents, ensuring deterministic low-overhead recording.
