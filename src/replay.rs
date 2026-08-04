use crate::trace::{read_trace_file_versioned, TraceEvent, TRACE_VERSION_2};
pub use crate::trace::{SYS_GETPID_X86_64, SYS_READ_X86_64};
use crate::tracer::{
    get_regs_x86_64, get_syscall_info, kill_and_reap, launch_traced_child, set_regs_x86_64,
    TraceeTermination,
};
use std::io;
use std::path::Path;
use std::ptr;

/// Represents an active live syscall in the replay loop awaiting its corresponding EXIT stop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingReplaySyscall {
    /// Non-substituted syscall passing through to the host kernel.
    Passthrough {
        number: u64,
        recorded_enter_event_id: u64,
    },
    /// `SYS_getpid` syscall suppressed at ENTRY, awaiting EXIT stop for recorded value injection.
    SubstitutedGetpid {
        recorded_enter_event_id: u64,
        recorded_exit_event_id: u64,
        recorded_result: i64,
    },
    /// `SYS_read` syscall suppressed at ENTRY, awaiting EXIT stop for memory and return injection.
    SubstitutedRead {
        recorded_enter_event_id: u64,
        recorded_exit_event_id: u64,
        recorded_result: i64,
        live_buffer_address: u64,
        live_count: u64,
    },
}

/// Writes an exact number of bytes into the stopped remote process address space using `process_vm_writev`.
pub fn write_process_memory_exact(
    pid: libc::pid_t,
    remote_addr: u64,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }

    let local_iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: bytes.len(),
    };

    let nwritten = unsafe { libc::process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0) };

    if nwritten < 0 {
        let err = io::Error::last_os_error();
        return Err(format!(
            "process_vm_writev failed for pid {} at 0x{:x} (len={}): {}",
            pid,
            remote_addr,
            bytes.len(),
            err
        ));
    }

    if (nwritten as usize) != bytes.len() {
        return Err(format!(
            "process_vm_writev short transfer for pid {}: requested {} bytes, wrote {}",
            pid,
            bytes.len(),
            nwritten
        ));
    }

    Ok(())
}

/// Executes `target` under deterministic replay substitution guided by the trace at `trace_path`.
pub fn run_replay(
    trace_path: &Path,
    target: &str,
    args: &[String],
) -> Result<TraceeTermination, String> {
    // 1. Read and validate trace file prior to target launch
    let parsed_trace = read_trace_file_versioned(trace_path)?;
    let version = parsed_trace.version;
    let events = parsed_trace.events;

    if events.is_empty() {
        return Err("M4 replay trace contains no events".to_string());
    }

    // 2. Validate prerequisites
    let recorded_tid = events[0].tid();
    for event in &events {
        if event.tid() != recorded_tid {
            return Err(
                "M4 replay does not support multi-threaded trace with multiple TIDs".to_string(),
            );
        }
    }

    let mut supported_substitutions_found = 0;
    for event in &events {
        if let TraceEvent::SyscallExit { number, result, .. } = event {
            if *number == SYS_GETPID_X86_64 {
                if *result <= 0 || *result > (i32::MAX as i64) {
                    return Err(format!(
                        "M4 replay trace contains invalid recorded getpid result {}",
                        result
                    ));
                }
                supported_substitutions_found += 1;
            } else if *number == SYS_READ_X86_64 {
                if version < TRACE_VERSION_2 && *result > 0 {
                    return Err(
                        "V1 trace cannot replay SYS_read memory output; record again with Trace Format V2"
                            .to_string(),
                    );
                }
                supported_substitutions_found += 1;
            }
        }
    }

    if supported_substitutions_found == 0 {
        return Err(
            "M4 replay trace contains no supported substitution (SYS_getpid or SYS_read)"
                .to_string(),
        );
    }

    // 3. Launch target process under ptrace
    let pid = launch_traced_child(target, args)?;

    // 4. Consume initial post-exec bootstrap execve exit stop
    let mut status: libc::c_int = 0;
    let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
    if wait_res < 0 {
        let err = io::Error::last_os_error();
        kill_and_reap(pid);
        return Err(format!(
            "initial waitpid awaiting bootstrap execve exit failed for pid {}: {}",
            pid, err
        ));
    }

    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80) {
        kill_and_reap(pid);
        return Err(format!(
            "expected initial bootstrap execve syscall exit stop for pid {}, got status 0x{:x}",
            pid, status
        ));
    }

    let bootstrap_info = match get_syscall_info(pid) {
        Ok(inf) => inf,
        Err(e) => {
            kill_and_reap(pid);
            return Err(e);
        }
    };

    if bootstrap_info.op != libc::PTRACE_SYSCALL_INFO_EXIT {
        kill_and_reap(pid);
        return Err(format!(
            "expected PTRACE_SYSCALL_INFO_EXIT for initial bootstrap stop on pid {}, got op {}",
            pid, bootstrap_info.op
        ));
    }

    // Resume tracee to enter main replay loop
    let cont_res = unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
        )
    };
    if cont_res != 0 {
        let err = io::Error::last_os_error();
        kill_and_reap(pid);
        return Err(format!(
            "PTRACE_SYSCALL after bootstrap exit failed for pid {}: {}",
            pid, err
        ));
    }

    // 5. Main replay loop
    let mut cursor: usize = 0;
    let mut pending_syscall: Option<PendingReplaySyscall> = None;
    let mut substitutions_performed: usize = 0;

    loop {
        let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
        if wait_res < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            kill_and_reap(pid);
            return Err(format!(
                "waitpid failed during replay loop for pid {}: {}",
                pid, err
            ));
        }

        if libc::WIFEXITED(status) {
            let exit_code = libc::WEXITSTATUS(status);
            if let Some(pending) = pending_syscall {
                let is_terminating_syscall = match pending {
                    PendingReplaySyscall::Passthrough { number, .. } => {
                        number == 60 || number == 231
                    }
                    _ => false,
                };
                if !is_terminating_syscall {
                    kill_and_reap(pid);
                    return Err(
                        "replay divergence: tracee exited while non-terminating syscall was pending"
                            .to_string(),
                    );
                }
            }
            if cursor < events.len() {
                let remaining = events.len() - cursor;
                let next_id = events[cursor].event_id();
                kill_and_reap(pid);
                return Err(format!(
                    "replay divergence: tracee exited prematurely at recorded event {}; {} recorded events remaining in trace",
                    next_id, remaining
                ));
            }
            if substitutions_performed == 0 {
                kill_and_reap(pid);
                return Err(
                    "replay failed: no substitution was performed during execution".to_string(),
                );
            }
            return Ok(TraceeTermination::Exited(exit_code));
        }

        if libc::WIFSIGNALED(status) {
            let term_sig = libc::WTERMSIG(status);
            kill_and_reap(pid);
            return Err(format!(
                "replay divergence: tracee terminated unexpectedly by signal {}",
                term_sig
            ));
        }

        if libc::WIFSTOPPED(status) {
            let stop_sig = libc::WSTOPSIG(status);
            let event = (status >> 16) as u32;

            if event != 0 {
                kill_and_reap(pid);
                return Err(format!(
                    "replay divergence: unexpected ptrace event {} for pid {}",
                    event, pid
                ));
            }

            let is_syscall_stop = stop_sig == (libc::SIGTRAP | 0x80);
            if !is_syscall_stop {
                kill_and_reap(pid);
                return Err(format!(
                    "replay divergence: unexpected signal delivery stop (sig={}) on pid {} during replay; signal replay is unsupported in M4",
                    stop_sig, pid
                ));
            }

            let info = match get_syscall_info(pid) {
                Ok(inf) => inf,
                Err(e) => {
                    kill_and_reap(pid);
                    return Err(e);
                }
            };

            match info.op {
                libc::PTRACE_SYSCALL_INFO_ENTRY => {
                    let entry = unsafe { info.u.entry };
                    let live_nr = entry.nr;

                    if pending_syscall.is_some() {
                        kill_and_reap(pid);
                        return Err(format!(
                            "replay divergence on pid {}: received syscall-enter nr={} while another syscall is still pending",
                            pid, live_nr
                        ));
                    }

                    if cursor >= events.len() {
                        kill_and_reap(pid);
                        return Err(format!(
                            "replay divergence: extra live syscall-enter nr={} on pid {} after trace exhausted",
                            live_nr, pid
                        ));
                    }

                    let rec_ev = &events[cursor];
                    cursor += 1;

                    match rec_ev {
                        TraceEvent::SyscallEnter {
                            event_id,
                            number: rec_nr,
                            args: rec_args,
                            ..
                        } => {
                            if *rec_nr != live_nr {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay divergence at recorded event {}: expected syscall-enter nr={}, observed live syscall-enter nr={} (pid={})",
                                    event_id, rec_nr, live_nr, pid
                                ));
                            }

                            if live_nr == SYS_GETPID_X86_64 {
                                if cursor >= events.len() {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "replay divergence: trace ended after SYS_getpid enter event {}",
                                        event_id
                                    ));
                                }

                                let next_rec = &events[cursor];
                                match next_rec {
                                    TraceEvent::SyscallExit {
                                        event_id: exit_ev_id,
                                        number: exit_nr,
                                        result: rec_result,
                                        ..
                                    } => {
                                        if *exit_nr != SYS_GETPID_X86_64 {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay divergence: recorded event {} is SyscallExit nr={}, expected SYS_getpid",
                                                exit_ev_id, exit_nr
                                            ));
                                        }

                                        let recorded_result = *rec_result;
                                        let mut regs = match get_regs_x86_64(pid) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                kill_and_reap(pid);
                                                return Err(e);
                                            }
                                        };

                                        if regs.orig_rax != SYS_GETPID_X86_64 {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay invariant violation: regs.orig_rax ({}) != SYS_getpid ({}) at syscall enter for pid {}",
                                                regs.orig_rax, SYS_GETPID_X86_64, pid
                                            ));
                                        }

                                        // Suppress kernel dispatch of SYS_getpid by modifying orig_rax to -1 (u64::MAX)
                                        regs.orig_rax = u64::MAX;
                                        if let Err(e) = set_regs_x86_64(pid, &regs) {
                                            kill_and_reap(pid);
                                            return Err(e);
                                        }

                                        pending_syscall =
                                            Some(PendingReplaySyscall::SubstitutedGetpid {
                                                recorded_enter_event_id: *event_id,
                                                recorded_exit_event_id: *exit_ev_id,
                                                recorded_result,
                                            });
                                    }
                                    _ => {
                                        kill_and_reap(pid);
                                        return Err(format!(
                                            "replay divergence: recorded event {} is not SyscallExit for SYS_getpid",
                                            next_rec.event_id()
                                        ));
                                    }
                                }
                            } else if live_nr == SYS_READ_X86_64 {
                                let live_count = entry.args[2];
                                let rec_count = rec_args[2];
                                if live_count != rec_count {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "replay divergence at recorded event {}: expected read count {}, observed live count {} (pid={})",
                                        event_id, rec_count, live_count, pid
                                    ));
                                }

                                if cursor >= events.len() {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "replay divergence: trace ended after SYS_read enter event {}",
                                        event_id
                                    ));
                                }

                                let next_rec = &events[cursor];
                                match next_rec {
                                    TraceEvent::SyscallExit {
                                        event_id: exit_ev_id,
                                        number: exit_nr,
                                        result: rec_result,
                                        ..
                                    } => {
                                        if *exit_nr != SYS_READ_X86_64 {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay divergence: recorded event {} is SyscallExit nr={}, expected SYS_read",
                                                exit_ev_id, exit_nr
                                            ));
                                        }

                                        if version < TRACE_VERSION_2 && *rec_result > 0 {
                                            kill_and_reap(pid);
                                            return Err(
                                                "V1 trace cannot replay SYS_read memory output; record again with Trace Format V2"
                                                    .to_string(),
                                            );
                                        }

                                        let live_buffer_address = entry.args[1];
                                        let recorded_result = *rec_result;

                                        let mut regs = match get_regs_x86_64(pid) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                kill_and_reap(pid);
                                                return Err(e);
                                            }
                                        };

                                        if regs.orig_rax != SYS_READ_X86_64 {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay invariant violation: regs.orig_rax ({}) != SYS_read ({}) at syscall enter for pid {}",
                                                regs.orig_rax, SYS_READ_X86_64, pid
                                            ));
                                        }

                                        // Suppress kernel dispatch of SYS_read by modifying orig_rax to -1 (u64::MAX)
                                        regs.orig_rax = u64::MAX;
                                        if let Err(e) = set_regs_x86_64(pid, &regs) {
                                            kill_and_reap(pid);
                                            return Err(e);
                                        }

                                        pending_syscall =
                                            Some(PendingReplaySyscall::SubstitutedRead {
                                                recorded_enter_event_id: *event_id,
                                                recorded_exit_event_id: *exit_ev_id,
                                                recorded_result,
                                                live_buffer_address,
                                                live_count,
                                            });
                                    }
                                    _ => {
                                        kill_and_reap(pid);
                                        return Err(format!(
                                            "replay divergence: recorded event {} is not SyscallExit for SYS_read",
                                            next_rec.event_id()
                                        ));
                                    }
                                }
                            } else {
                                pending_syscall = Some(PendingReplaySyscall::Passthrough {
                                    number: live_nr,
                                    recorded_enter_event_id: *event_id,
                                });
                            }
                        }
                        TraceEvent::SyscallExit {
                            event_id,
                            number: rec_nr,
                            ..
                        } => {
                            kill_and_reap(pid);
                            return Err(format!(
                                "replay divergence at recorded event {}: expected syscall-exit nr={}, observed live syscall-enter nr={} (pid={})",
                                event_id, rec_nr, live_nr, pid
                            ));
                        }
                        TraceEvent::KernelMemoryWrite { event_id, .. } => {
                            kill_and_reap(pid);
                            return Err(format!(
                                "replay divergence at recorded event {}: expected KernelMemoryWrite, observed live syscall-enter nr={} (pid={})",
                                event_id, live_nr, pid
                            ));
                        }
                    }

                    // Resume with PTRACE_SYSCALL
                    let cont_res = unsafe {
                        libc::ptrace(
                            libc::PTRACE_SYSCALL,
                            pid,
                            ptr::null_mut::<libc::c_void>(),
                            ptr::null_mut::<libc::c_void>(),
                        )
                    };
                    if cont_res != 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() != Some(libc::ESRCH) {
                            kill_and_reap(pid);
                            return Err(format!("PTRACE_SYSCALL failed for pid {}: {}", pid, err));
                        }
                    }
                    continue;
                }
                libc::PTRACE_SYSCALL_INFO_EXIT => {
                    let exit = unsafe { info.u.exit };
                    match pending_syscall.take() {
                        Some(PendingReplaySyscall::SubstitutedGetpid {
                            recorded_exit_event_id,
                            recorded_result,
                            ..
                        }) => {
                            if cursor >= events.len() {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay divergence on pid {}: trace exhausted at live syscall-exit for getpid",
                                    pid
                                ));
                            }

                            let rec_ev = &events[cursor];
                            cursor += 1;

                            if rec_ev.event_id() != recorded_exit_event_id {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay divergence: expected recorded exit event {}, got {}",
                                    recorded_exit_event_id,
                                    rec_ev.event_id()
                                ));
                            }

                            // Verify suppression sentinel (-ENOSYS)
                            let expected_sentinel = -(libc::ENOSYS as i64);
                            if exit.sval != expected_sentinel {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay suppression failure at event {}: expected suppression sentinel -ENOSYS ({}), observed exit result {} (is_error={}, pid={})",
                                    recorded_exit_event_id,
                                    expected_sentinel,
                                    exit.sval,
                                    exit.is_error,
                                    pid
                                ));
                            }

                            // Inject recorded result into RAX
                            let mut regs = match get_regs_x86_64(pid) {
                                Ok(r) => r,
                                Err(e) => {
                                    kill_and_reap(pid);
                                    return Err(e);
                                }
                            };

                            regs.rax = recorded_result as u64;
                            if let Err(e) = set_regs_x86_64(pid, &regs) {
                                kill_and_reap(pid);
                                return Err(e);
                            }

                            // Emit concise diagnostic
                            eprintln!(
                                "replay-substitute event={} syscall=getpid recorded={} live_pid={} suppressed={} injected={}",
                                recorded_exit_event_id,
                                recorded_result,
                                pid,
                                exit.sval,
                                recorded_result
                            );
                            substitutions_performed += 1;
                        }
                        Some(PendingReplaySyscall::SubstitutedRead {
                            recorded_exit_event_id,
                            recorded_result,
                            live_buffer_address,
                            live_count,
                            ..
                        }) => {
                            if cursor >= events.len() {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay divergence on pid {}: trace exhausted at live syscall-exit for read",
                                    pid
                                ));
                            }

                            let rec_ev = &events[cursor];
                            cursor += 1;

                            if rec_ev.event_id() != recorded_exit_event_id {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay divergence: expected recorded exit event {}, got {}",
                                    recorded_exit_event_id,
                                    rec_ev.event_id()
                                ));
                            }

                            // Verify suppression sentinel (-ENOSYS)
                            let expected_sentinel = -(libc::ENOSYS as i64);
                            if exit.sval != expected_sentinel {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay suppression failure at event {}: expected suppression sentinel -ENOSYS ({}), observed exit result {} (is_error={}, pid={})",
                                    recorded_exit_event_id,
                                    expected_sentinel,
                                    exit.sval,
                                    exit.is_error,
                                    pid
                                ));
                            }

                            if recorded_result > 0 {
                                if cursor >= events.len() {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "replay divergence on pid {}: trace exhausted awaiting KernelMemoryWrite for read exit event {}",
                                        pid, recorded_exit_event_id
                                    ));
                                }

                                let mem_ev = &events[cursor];
                                cursor += 1;

                                match mem_ev {
                                    TraceEvent::KernelMemoryWrite {
                                        event_id: mem_event_id,
                                        source_event_id,
                                        recorded_address,
                                        data,
                                        ..
                                    } => {
                                        if *source_event_id != recorded_exit_event_id {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay divergence: KernelMemoryWrite event {} source_event_id {} does not match read exit event {}",
                                                mem_event_id, source_event_id, recorded_exit_event_id
                                            ));
                                        }

                                        if data.len() != (recorded_result as usize) {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay divergence: KernelMemoryWrite event {} data length {} does not match recorded result {}",
                                                mem_event_id,
                                                data.len(),
                                                recorded_result
                                            ));
                                        }

                                        if (recorded_result as u64) > live_count {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "replay divergence: recorded read result {} exceeds live count {}",
                                                recorded_result, live_count
                                            ));
                                        }

                                        // Step 1: Write recorded bytes to the LIVE buffer address using process_vm_writev
                                        if let Err(e) = write_process_memory_exact(
                                            pid,
                                            live_buffer_address,
                                            data,
                                        ) {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "failed to write replay memory at event {}: {}",
                                                mem_event_id, e
                                            ));
                                        }

                                        // Step 2: Inject recorded result into RAX
                                        let mut regs = match get_regs_x86_64(pid) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                kill_and_reap(pid);
                                                return Err(e);
                                            }
                                        };

                                        regs.rax = recorded_result as u64;
                                        if let Err(e) = set_regs_x86_64(pid, &regs) {
                                            kill_and_reap(pid);
                                            return Err(e);
                                        }

                                        // Step 3: Emit concise read memory diagnostic
                                        eprintln!(
                                            "replay-memory event={} syscall=read recorded_addr=0x{:x} live_addr=0x{:x} len={} suppressed={} injected_result={}",
                                            mem_event_id,
                                            recorded_address,
                                            live_buffer_address,
                                            data.len(),
                                            exit.sval,
                                            recorded_result
                                        );
                                    }
                                    _ => {
                                        kill_and_reap(pid);
                                        return Err(format!(
                                            "replay divergence: expected KernelMemoryWrite after read exit event {}, got event {}",
                                            recorded_exit_event_id,
                                            mem_ev.event_id()
                                        ));
                                    }
                                }
                            } else {
                                // Zero or negative read result: no memory write, inject result into RAX directly
                                let mut regs = match get_regs_x86_64(pid) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        kill_and_reap(pid);
                                        return Err(e);
                                    }
                                };

                                regs.rax = recorded_result as u64;
                                if let Err(e) = set_regs_x86_64(pid, &regs) {
                                    kill_and_reap(pid);
                                    return Err(e);
                                }

                                eprintln!(
                                    "replay-substitute event={} syscall=read recorded={} live_pid={} suppressed={} injected={}",
                                    recorded_exit_event_id,
                                    recorded_result,
                                    pid,
                                    exit.sval,
                                    recorded_result
                                );
                            }

                            substitutions_performed += 1;
                        }
                        Some(PendingReplaySyscall::Passthrough { number, .. }) => {
                            if cursor >= events.len() {
                                kill_and_reap(pid);
                                return Err(format!(
                                    "replay divergence on pid {}: trace exhausted at live syscall-exit for nr={}",
                                    pid, number
                                ));
                            }

                            let rec_ev = &events[cursor];
                            cursor += 1;

                            match rec_ev {
                                TraceEvent::SyscallExit {
                                    event_id,
                                    number: rec_nr,
                                    ..
                                } => {
                                    if *rec_nr != number {
                                        kill_and_reap(pid);
                                        return Err(format!(
                                            "replay divergence at recorded event {}: expected syscall-exit nr={}, observed live syscall-exit nr={} (pid={})",
                                            event_id, rec_nr, number, pid
                                        ));
                                    }
                                }
                                TraceEvent::SyscallEnter { event_id, .. } => {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "replay divergence at recorded event {}: expected syscall-enter, observed live syscall-exit",
                                        event_id
                                    ));
                                }
                                TraceEvent::KernelMemoryWrite { event_id, .. } => {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "replay divergence at recorded event {}: expected KernelMemoryWrite, observed live syscall-exit",
                                        event_id
                                    ));
                                }
                            }
                        }
                        None => {
                            kill_and_reap(pid);
                            return Err(format!(
                                "replay divergence on pid {}: received unexpected syscall-exit with no pending live syscall-enter",
                                pid
                            ));
                        }
                    }

                    // Resume with PTRACE_SYSCALL
                    let cont_res = unsafe {
                        libc::ptrace(
                            libc::PTRACE_SYSCALL,
                            pid,
                            ptr::null_mut::<libc::c_void>(),
                            ptr::null_mut::<libc::c_void>(),
                        )
                    };
                    if cont_res != 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() != Some(libc::ESRCH) {
                            kill_and_reap(pid);
                            return Err(format!("PTRACE_SYSCALL failed for pid {}: {}", pid, err));
                        }
                    }
                    continue;
                }
                other => {
                    kill_and_reap(pid);
                    return Err(format!(
                        "replay divergence: unexpected ptrace_syscall_info op {} for pid {}",
                        other, pid
                    ));
                }
            }
        }

        kill_and_reap(pid);
        return Err(format!(
            "replay divergence: unexpected wait status 0x{:x} for pid {}",
            status, pid
        ));
    }
}
