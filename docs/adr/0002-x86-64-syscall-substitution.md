# ADR 0002: Native x86-64 Syscall Suppression and Deterministic Result Injection

## Status
Accepted

## Context
Milestones M0 through M2 established ptrace child lifecycle control, live syscall observation, and persistent binary trace storage in Trace Format V1. Milestone M3 introduces the first execution substitution mechanism: replaying a recorded syscall result into userspace so that the replaying process observes the recorded value instead of the live host kernel's value.

To prove that CAUSAL actually controls the execution and does not merely observe or overwrite results after the kernel executes side-effects, CAUSAL must:
1. Prevent the kernel from executing the live syscall;
2. Verify that the kernel skipped syscall execution;
3. Inject the recorded result into the architectural return register (`RAX`) before userspace resumes.

## Decision

We implement native x86-64 syscall suppression and return value injection for `SYS_getpid` (`nr = 39`) using the Linux kernel's standard `orig_ax` / `orig_rax` ptrace ABI.

### 1. Why `SYS_getpid` Was Chosen for M3
`SYS_getpid` is a pure, side-effect-free, register-returning syscall with no pointer arguments and no userspace memory buffers. It isolates the register suppression and substitution mechanism from memory replay complexity (which belongs to M4), providing an unambiguous, measurable baseline.

### 2. Why `orig_rax = -1` (u64::MAX) is Used for Suppression
In the Linux x86-64 syscall entry path (`arch/x86/entry/common.c`, `arch/x86/entry/entry_64.S`), the kernel saves userspace registers in `struct pt_regs`, with `orig_ax` holding the syscall number.
During ptrace syscall-entry tracing (`syscall_trace_enter`), if a tracer modifies `orig_ax` via `PTRACE_SETREGS` to an invalid syscall number such as `-1` (`(u64)-1` / `0xffff_ffff_ffff_ffff`), the kernel's dispatch logic detects `orig_ax < 0` or `orig_ax >= NR_syscalls` and skips calling the syscall handler.

### 3. Why `-ENOSYS` is Verified at Exit Stop Before Injection
Before dispatching a syscall, the Linux x86-64 entry path initializes `regs->ax` to `-ENOSYS` (`-38`). When syscall dispatch is skipped because `orig_ax == -1`, the kernel does not execute the syscall function and leaves `regs->ax` containing `-ENOSYS`.
At the subsequent syscall-exit stop, CAUSAL inspects the kernel exit status (`PTRACE_GET_SYSCALL_INFO` / `info.u.exit.sval`) to verify that the observed result equals `-(libc::ENOSYS as i64)`. This proves the kernel never executed `SYS_getpid`.

### 4. Why `RAX` is Overwritten at Syscall Exit Stop
At syscall-exit stop, the kernel has finished its syscall handling. Modifying `regs.rax` via `PTRACE_SETREGS` ensures that upon resumption with `PTRACE_SYSCALL`, the kernel restores userspace register state from `struct pt_regs`, returning the injected recorded value directly to the userspace caller in `RAX`.

### 5. Why `PTRACE_SYSEMU` Was Not Adopted for M3
While Linux x86-64 supports `PTRACE_SYSEMU`, using it would force global emulation of all syscalls. In M3, non-substituted syscalls (`mmap`, `brk`, `read`, `write`, `openat`, etc.) continue to execute live against the host kernel (passthrough). The `orig_rax = -1` suppression mechanism allows per-syscall suppression while keeping passthrough syscalls on standard `PTRACE_SYSCALL` tracing.

---

## Primary Source References
1. **Linux Kernel x86 Syscall Entry/Dispatch:**
   * `arch/x86/entry/common.c` (`syscall_trace_enter`, `do_syscall_64`)
   * `arch/x86/entry/entry_64.S`
   * `arch/x86/include/asm/syscall.h`
2. **Linux Kernel x86-64 Syscall Table:**
   * `arch/x86/entry/syscalls/syscall_64.tbl` (`39 common getpid sys_getpid`)
3. **Linux ptrace(2) Manual & UAPI:**
   * `man 2 ptrace` (`PTRACE_GETREGS`, `PTRACE_SETREGS`, `PTRACE_GET_SYSCALL_INFO`)
   * `include/uapi/linux/ptrace.h`

---

## Scope & Limitations
* Architecture-specific to Linux x86-64 native ELF targets.
* Single-threaded, single-process execution only.
* Substituted syscall in M3 is strictly `SYS_getpid`. Passthrough syscalls execute live against the kernel.
