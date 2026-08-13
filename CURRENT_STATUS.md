# CURRENT STATUS

## Current milestone
M5 — Memory-map model

## Status
PASS

## What works
* Normalized virtual memory-map model (`MemoryRegion` and `MemoryMapModel`) tracking process VMA address ranges, page alignment, permissions (`r`, `w`, `x`), sharing mode (`private`, `shared`), device IDs, inodes, file offsets, and descriptive labels.
* Authoritative procfs maps reader and robust parser (`parse_proc_maps_bytes`, `parse_proc_maps`, and `read_process_maps`) parsing `/proc/<pid>/maps` at the raw byte level without requiring valid UTF-8.
* Structural positional parsing of procfs maps lines without string search regressions on `inode = 0` or whitespace in labels.
* Trace Format V3 introducing three new event kinds:
  * `MemoryMapSnapshot` (`kind = 4`): Seed snapshot containing all initial VMAs at post-`execve` bootstrap boundary.
  * `MemoryMapAdd` (`kind = 5`): Region addition/replacement delta.
  * `MemoryMapRemove` (`kind = 6`): Region deletion/invalidation delta.
* Full backward compatibility for reading, parsing, and dumping Trace Format V1 and V2 files.
* Production recording (`causal record -o ...`) generating Trace Format V3 traces.
* Recording-time observation of memory mutation syscalls: `SYS_mmap` (9), `SYS_mprotect` (10), `SYS_munmap` (11), and `SYS_brk` (12) on Linux x86-64.
* Deterministic delta computation producing `MemoryMapRemove` followed by `MemoryMapAdd` deltas (sorted ascending by starting address) referencing the triggering `SyscallExit` event ID.
* Recording-time self-consistency verification: validating that applying deltas to the previous model reproduces the fresh `/proc/<pid>/maps` state identically.
* Offline historical query CLI: `causal maps <trace> <event-id>` reconstructing the exact virtual memory map state immediately after any specified execution event.
* Clean rejection of V1 and V2 traces for `causal maps` with single prefix diagnostic: `"causal: trace format V{} has no initial memory-map model; record again with V3"`.
* Deterministic replay compatibility with V3 traces: replay engine cleanly skips map metadata events while allowing mapping syscalls to execute live on the host kernel.
* Full replay support under V3 traces for both `SYS_read` kernel memory injection and `SYS_getpid` substitution.
* Comprehensive structural trace validation verifying monotonicity, non-overlapping regions, alignment, delta-source relationships, delta contiguity, and event pairings.

## What does not work
(Non-goals for M5):
* Full deterministic replay of arbitrary programs.
* Replay-time suppression or mocking of mapping syscalls (`mmap`, `mprotect`, `munmap`, `brk` execute live during replay).
* Virtual address forcing / fixed address remapping during replay.
* Memory page contents capture for mapped pages (only metadata / VMAs are modeled).
* Signal delivery recording and replay.
* Multi-threaded / multi-process recording and replay.

## Known limitations
* Linux x86-64 single-process, single-threaded native ELF targets only.
* Non-substituted syscalls execute live against host kernel and environment.
* Procfs `/proc/<pid>/maps` reading requires the tracee to be in a ptrace-stopped state.

## Verification performed
* `cargo fmt --check` — Passed.
* `cargo clippy --all-targets -- -D warnings` — Passed (0 warnings).
* `cargo test` — Passed (72/72 unit and integration tests across M0, M1, M2, M3, M4, and M5 suites).
* Canonical on-wire snapshot ordering: strictly rejects unsorted or overlapping wire snapshot region descriptors without silent normalization.
* Non-UTF-8 proc maps byte parser verification: preserved arbitrary label byte sequences and rendered lossy only at display time.
* Structural label extraction verification: proved exact label extraction for `inode = 0` (`[stack]`) and labels containing whitespace.
* Flagship mapping lifecycle verification (`map_model.c` fixture):
  * Observed initial `MemoryMapSnapshot` at event 1 preceding first `SyscallEnter`.
  * Verified 64KB `SYS_mmap` produced `MemoryMapAdd` delta referencing mmap exit event.
  * Verified 16KB subrange `SYS_mprotect` produced `MemoryMapRemove` for original range and `MemoryMapAdd` for 3 split subranges (RW, RX, RW).
  * Verified 16KB subrange `SYS_munmap` produced `MemoryMapRemove` and updated topology with an unmapped hole.
* `SYS_brk` heap expansion/shrinkage verification (`brk_model.c` fixture): verified heap growth and shrinkage produced matching delta pairs and historical query coverage.
* Failed syscall negative control (`map_fail.c` fixture): verified that failed mmap, mprotect, and munmap syscalls produced zero map deltas and preserved canonical model invariance across failed exits.
* Deterministic binary serialization: verified bit-for-bit identical binary output for repeated V3 synthetic streams.
* Independent V3 binary layout manual decode: verified header, snapshot kind 4, region count, memory region descriptor fields, delta kind 5/6, source event IDs, and footer magic.
* V3 replay compatibility: verified positive read replay with deleted/corrupted source and mixed getpid/read replay against V3 traces.
* 100-run recording stress test against mapping lifecycle fixture: 100/100 successful iterations with 0 failures or leaks.

## Current architecture
* `src/main.rs`: CLI entrypoint handling `record`, `dump`, `replay`, and `maps`.
* `src/maps.rs`: `MemoryRegion`, `MemoryMapModel`, procfs maps byte parsing, diff computation, and address inspection.
* `src/trace.rs`: Binary Trace Format V1/V2/V3 codec, `TraceWriter`, `ParsedTrace`, historical query reconstruction (`reconstruct_maps_at_event`), and `dump_trace`.
* `src/tracer.rs`: Ptrace supervisor with initial snapshot capture, mapping exit delta tracking, self-consistency verification, and remote memory reading.
* `src/replay.rs`: Deterministic replay engine with metadata skipping, syscall suppression, and memory injection.
* `docs/adr/0001-trace-format-v1.md`: Trace Format V1 specification.
* `docs/adr/0002-x86-64-syscall-substitution.md`: x86-64 syscall suppression and return injection design.
* `docs/adr/0003-trace-format-v2-memory-write.md`: Trace Format V2 and `KernelMemoryWrite` design.
* `docs/adr/0004-memory-map-model-and-trace-v3.md`: Trace Format V3 and Virtual Memory-Map Model design.

## Next exact task
M6 — Signals
