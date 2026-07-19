use crate::trace::TraceWriter;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;

/// Represents the lifecycle state of the child process during launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchState {
    /// Child has forked and is expected to raise SIGSTOP after PTRACE_TRACEME.
    AwaitingStartupStop,
    /// Child has been configured with options and resumed; awaiting execve completion.
    AwaitingExec,
    /// Target program has successfully executed and is actively running under syscall tracing.
    Running,
}

/// Final observed termination outcome of the tracee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceeTermination {
    /// Process exited normally with the given exit code.
    Exited(i32),
    /// Process was terminated by the given signal number.
    Signaled(i32),
}

/// In-memory representation of an active syscall entry awaiting its exit stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSyscall {
    pub tid: libc::pid_t,
    pub number: u64,
    pub args: [u64; 6],
}

/// Structured error payload sent across the child->parent launch pipe on pre-exec failure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LaunchErrorPayload {
    stage: u32,
    errno: i32,
}

const STAGE_TRACEME: u32 = 1;
const STAGE_STARTUP_STOP: u32 = 2;
const STAGE_EXEC: u32 = 3;

/// Formats an OS errno into a readable message.
fn format_errno(errno: i32) -> String {
    format!("{}", io::Error::from_raw_os_error(errno))
}

/// Executes `target` with `args` under ptrace supervision, optionally streaming events to `trace_path`.
///
/// Implements the M2 ptrace lifecycle with persistent V1 binary trace encoding:
/// 1. Optionally creates output trace file and writes V1 header before fork.
/// 2. Prepares arguments in parent before fork.
/// 3. Creates a close-on-exec pipe for error reporting.
/// 4. In child: PTRACE_TRACEME -> raise(SIGSTOP) -> execvp.
/// 5. In parent: Observes startup SIGSTOP -> sets PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD -> PTRACE_CONT.
/// 6. Observes PTRACE_EVENT_EXEC -> transitions to Running -> PTRACE_SYSCALL.
/// 7. In event loop:
///    - Consumes initial execve bootstrap exit stop.
///    - Uses PTRACE_GET_SYSCALL_INFO to classify ENTRY and EXIT phases.
///    - Pairs syscall entries with exits, prints raw output, and streams to `TraceWriter` if configured.
///    - Preserves and reinjects ordinary signals using PTRACE_SYSCALL.
///    - Finalizes trace with completion footer on normal exit or signal termination.
///    - Reaps the child process.
pub fn run_tracee(
    target: &str,
    args: &[String],
    trace_path: Option<&Path>,
) -> Result<TraceeTermination, String> {
    // If persistent recording is requested, open/truncate output file and write V1 header prior to launch.
    let mut trace_writer = match trace_path {
        Some(path) => {
            let file = File::create(path)
                .map_err(|e| format!("cannot create trace '{}': {}", path.display(), e))?;
            let writer = TraceWriter::new(BufWriter::new(file))
                .map_err(|e| format!("failed to initialize trace header: {}", e))?;
            Some(writer)
        }
        None => None,
    };

    let result = run_tracee_inner(target, args, &mut trace_writer);

    if result.is_err() {
        // If recording failed prematurely, remove incomplete trace file so a corrupt/unfinalized
        // file is not left presented as a valid trace.
        if let Some(path) = trace_path {
            let _ = fs::remove_file(path);
        }
    }

    result
}

fn run_tracee_inner(
    target: &str,
    args: &[String],
    trace_writer: &mut Option<TraceWriter<BufWriter<File>>>,
) -> Result<TraceeTermination, String> {
    // 1. Prepare target and arguments as CStrings prior to fork.
    // This avoids heap allocation and complex runtime code in the child process between fork and exec.
    let c_target = CString::new(target)
        .map_err(|_| format!("target path contains interior null byte: {:?}", target))?;

    let mut c_args = Vec::with_capacity(args.len() + 1);
    c_args.push(c_target.clone());
    for arg in args {
        let c_arg = CString::new(arg.as_str())
            .map_err(|_| format!("argument contains interior null byte: {:?}", arg))?;
        c_args.push(c_arg);
    }

    let mut c_argv: Vec<*const libc::c_char> = Vec::with_capacity(c_args.len() + 1);
    for arg in &c_args {
        c_argv.push(arg.as_ptr());
    }
    c_argv.push(ptr::null());

    // 2. Create error reporting pipe with O_CLOEXEC.
    // If execvp succeeds, the pipe write end is automatically closed by the kernel (producing EOF in parent).
    // If any step before or during exec fails, child writes LaunchErrorPayload and exits.
    let mut pipe_fds = [0_i32; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "failed to create launch synchronization pipe: {}",
            io::Error::last_os_error()
        ));
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

    // 3. Fork child process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
        return Err(format!("fork failed: {}", err));
    }

    if pid == 0 {
        // --- CHILD PROCESS ---
        // Async-signal-safe path: no allocations, no locks, no complex runtime.
        unsafe {
            libc::close(pipe_read);

            // Establish tracing relationship.
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            ) != 0
            {
                let errno = *libc::__errno_location();
                let payload = LaunchErrorPayload {
                    stage: STAGE_TRACEME,
                    errno,
                };
                let _ = libc::write(
                    pipe_write,
                    &payload as *const LaunchErrorPayload as *const libc::c_void,
                    std::mem::size_of::<LaunchErrorPayload>(),
                );
                libc::close(pipe_write);
                libc::_exit(127);
            }

            // Raise intentional startup SIGSTOP to synchronize with parent tracer.
            if libc::raise(libc::SIGSTOP) != 0 {
                let errno = *libc::__errno_location();
                let payload = LaunchErrorPayload {
                    stage: STAGE_STARTUP_STOP,
                    errno,
                };
                let _ = libc::write(
                    pipe_write,
                    &payload as *const LaunchErrorPayload as *const libc::c_void,
                    std::mem::size_of::<LaunchErrorPayload>(),
                );
                libc::close(pipe_write);
                libc::_exit(127);
            }

            // Execute target. On success, O_CLOEXEC closes pipe_write.
            libc::execvp(c_target.as_ptr(), c_argv.as_ptr());

            // If execvp returns, it failed.
            let errno = *libc::__errno_location();
            let payload = LaunchErrorPayload {
                stage: STAGE_EXEC,
                errno,
            };
            let _ = libc::write(
                pipe_write,
                &payload as *const LaunchErrorPayload as *const libc::c_void,
                std::mem::size_of::<LaunchErrorPayload>(),
            );
            libc::close(pipe_write);
            libc::_exit(127);
        }
    }

    // --- PARENT TRACER PROCESS ---
    unsafe {
        libc::close(pipe_write);
    }

    let mut state = LaunchState::AwaitingStartupStop;
    let mut status: libc::c_int = 0;

    // Helper closure to read launch error from pipe (if any).
    let read_launch_error = || -> Option<LaunchErrorPayload> {
        let mut payload = LaunchErrorPayload { stage: 0, errno: 0 };
        let mut total_read = 0;
        let expected = std::mem::size_of::<LaunchErrorPayload>();
        let buf = &mut payload as *mut LaunchErrorPayload as *mut u8;

        while total_read < expected {
            let n = unsafe {
                libc::read(
                    pipe_read,
                    buf.add(total_read) as *mut libc::c_void,
                    expected - total_read,
                )
            };
            if n > 0 {
                total_read += n as usize;
            } else if n == 0 {
                break; // EOF
            } else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
        }

        if total_read == expected {
            Some(payload)
        } else {
            None
        }
    };

    // 4. Wait for deliberate startup SIGSTOP.
    let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
    if wait_res < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(pipe_read) };
        return Err(format!(
            "initial waitpid for pid {} failed in state {:?}: {}",
            pid, state, err
        ));
    }

    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        // Child did not enter expected startup stop. Check launch pipe for error.
        let launch_err = read_launch_error();
        unsafe { libc::close(pipe_read) };

        if let Some(err_payload) = launch_err {
            match err_payload.stage {
                STAGE_TRACEME => {
                    return Err(format!(
                        "PTRACE_TRACEME failed in child: {}",
                        format_errno(err_payload.errno)
                    ));
                }
                STAGE_STARTUP_STOP => {
                    return Err(format!(
                        "startup SIGSTOP failed in child: {}",
                        format_errno(err_payload.errno)
                    ));
                }
                STAGE_EXEC => {
                    return Err(format!(
                        "exec failed for '{}': {}",
                        target,
                        format_errno(err_payload.errno)
                    ));
                }
                other => {
                    return Err(format!(
                        "unknown child startup stage {} failure: {}",
                        other,
                        format_errno(err_payload.errno)
                    ));
                }
            }
        }

        return Err(format!(
            "unexpected initial stop state for pid {} in state {:?}: raw status=0x{:x}, WIFSTOPPED={}, WSTOPSIG={}, WIFEXITED={}, WIFSIGNALED={}",
            pid,
            state,
            status,
            libc::WIFSTOPPED(status),
            libc::WSTOPSIG(status),
            libc::WIFEXITED(status),
            libc::WIFSIGNALED(status)
        ));
    }

    // 5. Configure PTRACE_O_TRACEEXEC and PTRACE_O_TRACESYSGOOD.
    // PTRACE_O_TRACEEXEC delivers PTRACE_EVENT_EXEC upon successful exec.
    // PTRACE_O_TRACESYSGOOD sets bit 7 in signal number (SIGTRAP | 0x80) for syscall stops.
    let ptrace_options = libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACESYSGOOD;
    let opt_res = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>().add(ptrace_options as usize),
        )
    };
    if opt_res != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(pipe_read) };
        return Err(format!(
            "PTRACE_SETOPTIONS failed for pid {} in state {:?}: {}",
            pid, state, err
        ));
    }

    // Resume child from deliberate startup stop (signal 0: do not reinject SIGSTOP).
    let cont_res = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
        )
    };
    if cont_res != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(pipe_read) };
        return Err(format!(
            "PTRACE_CONT after startup stop failed for pid {} in state {:?}: {}",
            pid, state, err
        ));
    }
    state = LaunchState::AwaitingExec;

    // 6. Wait for exec event or launch failure.
    let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
    if wait_res < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(pipe_read) };
        return Err(format!(
            "waitpid awaiting exec for pid {} in state {:?}: {}",
            pid, state, err
        ));
    }

    // Check launch error pipe.
    let launch_err = read_launch_error();
    unsafe { libc::close(pipe_read) };

    if let Some(err_payload) = launch_err {
        // Child failed exec or pre-exec setup. Ensure child is reaped.
        if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
            unsafe {
                let _ = libc::waitpid(pid, &mut status, 0);
            }
        }
        match err_payload.stage {
            STAGE_TRACEME => {
                return Err(format!(
                    "launch failed: PTRACE_TRACEME failed: {}",
                    format_errno(err_payload.errno)
                ));
            }
            STAGE_STARTUP_STOP => {
                return Err(format!(
                    "launch failed: startup SIGSTOP failed: {}",
                    format_errno(err_payload.errno)
                ));
            }
            STAGE_EXEC => {
                return Err(format!(
                    "launch failed: exec failed for '{}': {}",
                    target,
                    format_errno(err_payload.errno)
                ));
            }
            other => {
                return Err(format!(
                    "launch failed at stage {}: {}",
                    other,
                    format_errno(err_payload.errno)
                ));
            }
        }
    }

    // Positive recognition of successful exec:
    // With PTRACE_O_TRACEEXEC, wait status must be a stop with SIGTRAP and PTRACE_EVENT_EXEC in upper bits.
    let is_exec_event = libc::WIFSTOPPED(status)
        && libc::WSTOPSIG(status) == libc::SIGTRAP
        && ((status >> 16) as libc::c_int) == libc::PTRACE_EVENT_EXEC;

    if !is_exec_event {
        return Err(format!(
            "failed to observe PTRACE_EVENT_EXEC for pid {} in state {:?}: raw status=0x{:x}, WIFSTOPPED={}, WSTOPSIG={}, event={}",
            pid,
            state,
            status,
            libc::WIFSTOPPED(status),
            libc::WSTOPSIG(status),
            (status >> 16)
        ));
    }

    // Successfully launched! Transition state to Running.
    state = LaunchState::Running;

    // Resume tracee using PTRACE_SYSCALL so all subsequent syscall entry/exit stops are intercepted.
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
        return Err(format!(
            "PTRACE_SYSCALL after exec failed for pid {} in state {:?}: {}",
            pid, state, err
        ));
    }

    // Immediately following PTRACE_EVENT_EXEC, the first syscall stop encountered is the EXIT
    // stop corresponding to the initial execve completion. This one-time bootstrap condition
    // is consumed so only target userspace syscalls are reported.
    let mut is_bootstrap_exec_exit = true;
    let mut pending_syscall: Option<PendingSyscall> = None;

    // 7. Main event loop: observe syscall entry/exit stops, stream to writer, preserve signals, detect termination.
    loop {
        let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
        if wait_res < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!(
                "waitpid failed in event loop for pid {} in state {:?}: {}",
                pid, state, err
            ));
        }

        if libc::WIFEXITED(status) {
            let exit_code = libc::WEXITSTATUS(status);
            if let Some(ref mut writer) = trace_writer {
                writer
                    .finish()
                    .map_err(|e| format!("failed to finalize trace footer: {}", e))?;
            }
            println!("child exited with status {}", exit_code);
            return Ok(TraceeTermination::Exited(exit_code));
        }

        if libc::WIFSIGNALED(status) {
            let term_sig = libc::WTERMSIG(status);
            if let Some(ref mut writer) = trace_writer {
                writer
                    .finish()
                    .map_err(|e| format!("failed to finalize trace footer: {}", e))?;
            }
            println!("child terminated by signal {}", term_sig);
            return Ok(TraceeTermination::Signaled(term_sig));
        }

        if libc::WIFSTOPPED(status) {
            let stop_sig = libc::WSTOPSIG(status);
            let event = (status >> 16) as u32;

            if event != 0 {
                // In M2, no ptrace events beyond initial exec are supported.
                return Err(format!(
                    "unexpected ptrace event {} for pid {}: raw status=0x{:x}, stop_sig={}, state={:?}",
                    event, pid, status, stop_sig, state
                ));
            }

            // Check if this stop is a syscall-stop marked by PTRACE_O_TRACESYSGOOD (SIGTRAP | 0x80).
            let is_syscall_stop = stop_sig == (libc::SIGTRAP | 0x80);

            if is_syscall_stop {
                let mut info: MaybeUninit<libc::ptrace_syscall_info> = MaybeUninit::uninit();
                let get_res = unsafe {
                    libc::ptrace(
                        libc::PTRACE_GET_SYSCALL_INFO,
                        pid,
                        std::mem::size_of::<libc::ptrace_syscall_info>() as *mut libc::c_void,
                        info.as_mut_ptr() as *mut libc::c_void,
                    )
                };
                if get_res < 0 {
                    let err = io::Error::last_os_error();
                    return Err(format!(
                        "PTRACE_GET_SYSCALL_INFO failed for pid {}: {}",
                        pid, err
                    ));
                }

                let info = unsafe { info.assume_init() };
                match info.op {
                    libc::PTRACE_SYSCALL_INFO_ENTRY => {
                        let entry = unsafe { info.u.entry };
                        if let Some(prev) = pending_syscall {
                            return Err(format!(
                                "syscall pairing invariant violation for pid {}: received ENTRY nr={} while previous syscall ENTRY nr={} is still pending",
                                pid, entry.nr, prev.number
                            ));
                        }
                        let number = entry.nr;
                        let args = entry.args;
                        pending_syscall = Some(PendingSyscall {
                            tid: pid,
                            number,
                            args,
                        });
                        println!(
                            "syscall-enter tid={} nr={} args=[{}, {}, {}, {}, {}, {}]",
                            pid, number, args[0], args[1], args[2], args[3], args[4], args[5]
                        );
                        if let Some(ref mut writer) = trace_writer {
                            writer
                                .write_syscall_enter(pid as u32, number, args)
                                .map_err(|e| {
                                    format!("failed to write SyscallEnter trace event: {}", e)
                                })?;
                        }
                    }
                    libc::PTRACE_SYSCALL_INFO_EXIT => {
                        let exit = unsafe { info.u.exit };
                        if is_bootstrap_exec_exit {
                            // Consume the initial post-exec bootstrap exit stop.
                            is_bootstrap_exec_exit = false;
                        } else {
                            match pending_syscall.take() {
                                Some(pending) => {
                                    println!(
                                        "syscall-exit  tid={} nr={} result={}",
                                        pid, pending.number, exit.sval
                                    );
                                    if let Some(ref mut writer) = trace_writer {
                                        writer
                                            .write_syscall_exit(
                                                pid as u32,
                                                pending.number,
                                                exit.sval,
                                            )
                                            .map_err(|e| {
                                                format!(
                                                    "failed to write SyscallExit trace event: {}",
                                                    e
                                                )
                                            })?;
                                    }
                                }
                                None => {
                                    return Err(format!(
                                        "syscall pairing invariant violation for pid {}: received unexpected EXIT (rval={}, is_error={}) with no pending syscall ENTRY",
                                        pid, exit.sval, exit.is_error
                                    ));
                                }
                            }
                        }
                    }
                    libc::PTRACE_SYSCALL_INFO_SECCOMP => {
                        return Err(format!(
                            "unsupported seccomp stop for pid {}: nr={}",
                            pid,
                            unsafe { info.u.seccomp.nr }
                        ));
                    }
                    libc::PTRACE_SYSCALL_INFO_NONE => {
                        return Err(format!(
                            "tracing invariant violation for pid {}: PTRACE_GET_SYSCALL_INFO returned NONE at syscall stop (status=0x{:x})",
                            pid, status
                        ));
                    }
                    other => {
                        return Err(format!(
                            "unexpected ptrace_syscall_info op {} for pid {}",
                            other, pid
                        ));
                    }
                }

                // Continue to next syscall stop with signal 0 (consuming syscall trap).
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
                    // If ESRCH, tracee may have already terminated; continue loop to reap via waitpid.
                    if err.raw_os_error() != Some(libc::ESRCH) {
                        return Err(format!(
                            "PTRACE_SYSCALL failed for pid {} in state {:?}: {}",
                            pid, state, err
                        ));
                    }
                }
                continue;
            }

            // Ordinary signal-delivery stop (e.g. SIGTERM, plain user SIGTRAP, etc.):
            // Preserve tracee behavior by reinjecting the signal upon resumption with PTRACE_SYSCALL.
            let cont_res = unsafe {
                libc::ptrace(
                    libc::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut::<libc::c_void>(),
                    ptr::null_mut::<libc::c_void>().add(stop_sig as usize),
                )
            };
            if cont_res != 0 {
                let err = io::Error::last_os_error();
                // If ESRCH, tracee may have already terminated; continue loop to reap via waitpid.
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(format!(
                        "PTRACE_SYSCALL reinjecting signal {} failed for pid {} in state {:?}: {}",
                        stop_sig, pid, state, err
                    ));
                }
            }
            continue;
        }

        // Any other wait status is outside M2 lifecycle model.
        return Err(format!(
            "unexpected wait status 0x{:x} for pid {} in state {:?}: WIFCONTINUED={}",
            status,
            pid,
            state,
            libc::WIFCONTINUED(status)
        ));
    }
}
