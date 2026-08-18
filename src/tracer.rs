use crate::maps::{read_process_maps, MemoryMapModel};
use crate::trace::{
    is_substituted_syscall, substituted_syscall_name, TraceWriter, SYS_BRK_X86_64, SYS_MMAP_X86_64,
    SYS_MPROTECT_X86_64, SYS_MUNMAP_X86_64, SYS_READ_X86_64, TRACE_VERSION_3,
};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchState {
    AwaitingStartupStop,

    AwaitingExec,

    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceeTermination {
    Exited(i32),

    Signaled(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSyscall {
    pub tid: libc::pid_t,
    pub number: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LaunchErrorPayload {
    stage: u32,
    errno: i32,
}

const STAGE_TRACEME: u32 = 1;
const STAGE_STARTUP_STOP: u32 = 2;
const STAGE_EXEC: u32 = 3;

pub fn format_errno(errno: i32) -> String {
    format!("{}", io::Error::from_raw_os_error(errno))
}

pub fn get_regs_x86_64(pid: libc::pid_t) -> Result<libc::user_regs_struct, String> {
    let mut regs = MaybeUninit::<libc::user_regs_struct>::uninit();
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            regs.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if res != 0 {
        let err = io::Error::last_os_error();
        return Err(format!("PTRACE_GETREGS failed for pid {}: {}", pid, err));
    }
    Ok(unsafe { regs.assume_init() })
}

pub fn set_regs_x86_64(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Result<(), String> {
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            regs as *const libc::user_regs_struct as *const libc::c_void,
        )
    };
    if res != 0 {
        let err = io::Error::last_os_error();
        return Err(format!("PTRACE_SETREGS failed for pid {}: {}", pid, err));
    }
    Ok(())
}

pub fn get_syscall_info(pid: libc::pid_t) -> Result<libc::ptrace_syscall_info, String> {
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
    Ok(unsafe { info.assume_init() })
}

pub fn get_signal_info(pid: libc::pid_t) -> Result<libc::siginfo_t, String> {
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETSIGINFO,
            pid,
            ptr::null_mut::<libc::c_void>(),
            info.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if res != 0 {
        let err = io::Error::last_os_error();
        return Err(format!("PTRACE_GETSIGINFO failed for pid {}: {}", pid, err));
    }
    Ok(unsafe { info.assume_init() })
}

pub fn set_signal_info(pid: libc::pid_t, info: &libc::siginfo_t) -> Result<(), String> {
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_SETSIGINFO,
            pid,
            ptr::null_mut::<libc::c_void>(),
            info as *const libc::siginfo_t as *const libc::c_void,
        )
    };
    if res != 0 {
        let err = io::Error::last_os_error();
        return Err(format!("PTRACE_SETSIGINFO failed for pid {}: {}", pid, err));
    }
    Ok(())
}

pub fn kill_and_reap(pid: libc::pid_t) {
    unsafe {
        let _ = libc::kill(pid, libc::SIGKILL);
        let mut status: libc::c_int = 0;
        loop {
            let res = libc::waitpid(pid, &mut status, 0);
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                break;
            }
        }
    }
}

pub fn read_process_memory_exact(
    pid: libc::pid_t,
    remote_addr: u64,
    len: usize,
) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0_u8; len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: len,
    };

    let nread = unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };

    if nread < 0 {
        let err = io::Error::last_os_error();
        return Err(format!(
            "process_vm_readv failed for pid {} at 0x{:x} (len={}): {}",
            pid, remote_addr, len, err
        ));
    }

    if (nread as usize) != len {
        return Err(format!(
            "process_vm_readv short transfer for pid {}: requested {} bytes, read {}",
            pid, len, nread
        ));
    }

    Ok(buf)
}

pub fn launch_traced_child(target: &str, args: &[String]) -> Result<libc::pid_t, String> {
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

    let mut pipe_fds = [0_i32; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "failed to create launch synchronization pipe: {}",
            io::Error::last_os_error()
        ));
    }
    let pipe_read = pipe_fds[0];
    let pipe_write = pipe_fds[1];

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
        unsafe {
            libc::close(pipe_read);

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

            libc::execvp(c_target.as_ptr(), c_argv.as_ptr());

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

    unsafe {
        libc::close(pipe_write);
    }

    let mut state = LaunchState::AwaitingStartupStop;
    let mut status: libc::c_int = 0;

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
                break;
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

    let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
    if wait_res < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(pipe_read) };
        return Err(format!(
            "waitpid awaiting exec for pid {} in state {:?}: {}",
            pid, state, err
        ));
    }

    let launch_err = read_launch_error();
    unsafe { libc::close(pipe_read) };

    if let Some(err_payload) = launch_err {
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

    Ok(pid)
}

pub fn run_tracee(
    target: &str,
    args: &[String],
    trace_path: Option<&Path>,
) -> Result<TraceeTermination, String> {
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
    let pid = launch_traced_child(target, args)?;
    let mut status: libc::c_int = 0;

    let mut is_bootstrap_exec_exit = true;
    let mut pending_syscall: Option<PendingSyscall> = None;
    let mut interrupted_syscall: Option<u64> = None;
    let mut current_map_model: Option<MemoryMapModel> = None;
    let mut last_injected_signal: Option<i32> = None;

    loop {
        let wait_res = unsafe { libc::waitpid(pid, &mut status, 0) };
        if wait_res < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            kill_and_reap(pid);
            return Err(format!(
                "waitpid failed in event loop for pid {}: {}",
                pid, err
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
                if last_injected_signal != Some(term_sig) {
                    kill_and_reap(pid);
                    return Err(format!(
                        "pid {} terminated by signal {} with no preceding recorded/injected signal delivery stop",
                        pid, term_sig
                    ));
                }
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
                kill_and_reap(pid);
                return Err(format!(
                    "unexpected ptrace event {} for pid {}: raw status=0x{:x}, stop_sig={}",
                    event, pid, status, stop_sig
                ));
            }

            let is_syscall_stop = stop_sig == (libc::SIGTRAP | 0x80);

            if is_syscall_stop {
                last_injected_signal = None;
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
                        if let Some(prev) = pending_syscall {
                            kill_and_reap(pid);
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
                        interrupted_syscall = None;
                        println!(
                            "syscall-enter tid={} nr={} args=[{}, {}, {}, {}, {}, {}]",
                            pid, number, args[0], args[1], args[2], args[3], args[4], args[5]
                        );
                        if let Some(ref mut writer) = trace_writer {
                            writer
                                .write_syscall_enter(pid as u32, number, args)
                                .map_err(|e| {
                                    kill_and_reap(pid);
                                    format!("failed to write SyscallEnter trace event: {}", e)
                                })?;
                        }
                    }
                    libc::PTRACE_SYSCALL_INFO_EXIT => {
                        let exit = unsafe { info.u.exit };
                        if is_bootstrap_exec_exit {
                            is_bootstrap_exec_exit = false;

                            if let Some(ref mut writer) = trace_writer {
                                if writer.version() >= TRACE_VERSION_3 {
                                    let initial_maps = match read_process_maps(pid) {
                                        Ok(m) => m,
                                        Err(e) => {
                                            kill_and_reap(pid);
                                            return Err(format!(
                                                "failed to capture initial process maps for pid {}: {}",
                                                pid, e
                                            ));
                                        }
                                    };
                                    writer
                                        .write_memory_map_snapshot(
                                            pid as u32,
                                            initial_maps.regions(),
                                        )
                                        .map_err(|e| {
                                            kill_and_reap(pid);
                                            format!(
                                                "failed to write MemoryMapSnapshot trace event: {}",
                                                e
                                            )
                                        })?;
                                    current_map_model = Some(initial_maps);
                                }
                            }
                        } else {
                            match pending_syscall.take() {
                                Some(pending) => {
                                    println!(
                                        "syscall-exit  tid={} nr={} result={}",
                                        pid, pending.number, exit.sval
                                    );
                                    if is_substituted_syscall(pending.number) && exit.sval < 0 {
                                        interrupted_syscall = Some(pending.number);
                                    } else {
                                        interrupted_syscall = None;
                                    }
                                    if let Some(ref mut writer) = trace_writer {
                                        let exit_event_id = writer
                                            .write_syscall_exit(
                                                pid as u32,
                                                pending.number,
                                                exit.sval,
                                            )
                                            .map_err(|e| {
                                                kill_and_reap(pid);
                                                format!(
                                                    "failed to write SyscallExit trace event: {}",
                                                    e
                                                )
                                            })?;

                                        if pending.number == SYS_READ_X86_64 && exit.sval > 0 {
                                            let nbytes = exit.sval as usize;
                                            let buf_addr = pending.args[1];
                                            let data = match read_process_memory_exact(
                                                pid, buf_addr, nbytes,
                                            ) {
                                                Ok(d) => d,
                                                Err(e) => {
                                                    kill_and_reap(pid);
                                                    return Err(format!(
                                                        "failed to capture read memory output for pid {}: {}",
                                                        pid, e
                                                    ));
                                                }
                                            };
                                            writer
                                                .write_kernel_memory_write(
                                                    pid as u32,
                                                    exit_event_id,
                                                    buf_addr,
                                                    &data,
                                                )
                                                .map_err(|e| {
                                                    kill_and_reap(pid);
                                                    format!(
                                                        "failed to write KernelMemoryWrite trace event: {}",
                                                        e
                                                    )
                                                })?;
                                        }

                                        if (pending.number == SYS_MMAP_X86_64
                                            || pending.number == SYS_MPROTECT_X86_64
                                            || pending.number == SYS_MUNMAP_X86_64
                                            || pending.number == SYS_BRK_X86_64)
                                            && writer.version() >= TRACE_VERSION_3
                                        {
                                            let fresh_maps = match read_process_maps(pid) {
                                                Ok(m) => m,
                                                Err(e) => {
                                                    kill_and_reap(pid);
                                                    return Err(format!(
                                                            "failed to read process maps after syscall nr={} for pid {}: {}",
                                                            pending.number, pid, e
                                                        ));
                                                }
                                            };
                                            if let Some(ref mut cur_model) = current_map_model {
                                                let (removes, adds) = cur_model.diff(&fresh_maps);

                                                if (pending.number == SYS_MMAP_X86_64
                                                    || pending.number == SYS_MPROTECT_X86_64
                                                    || pending.number == SYS_MUNMAP_X86_64)
                                                    && exit.sval < 0
                                                {
                                                    if !removes.is_empty() || !adds.is_empty() {
                                                        kill_and_reap(pid);
                                                        return Err(format!(
                                                                "failed mapping syscall nr={} (rval={}) produced unexpected map changes",
                                                                pending.number, exit.sval
                                                            ));
                                                    }
                                                } else {
                                                    for r in &removes {
                                                        writer
                                                                .write_memory_map_remove(
                                                                    pid as u32,
                                                                    exit_event_id,
                                                                    r,
                                                                )
                                                                .map_err(|e| {
                                                                    kill_and_reap(pid);
                                                                    format!(
                                                                        "failed to write MemoryMapRemove trace event: {}",
                                                                        e
                                                                    )
                                                                })?;
                                                    }
                                                    for a in &adds {
                                                        writer
                                                                .write_memory_map_add(
                                                                    pid as u32,
                                                                    exit_event_id,
                                                                    a,
                                                                )
                                                                .map_err(|e| {
                                                                    kill_and_reap(pid);
                                                                    format!(
                                                                        "failed to write MemoryMapAdd trace event: {}",
                                                                        e
                                                                    )
                                                                })?;
                                                    }

                                                    let mut check_model = cur_model.clone();
                                                    for r in &removes {
                                                        if let Err(e) = check_model.apply_remove(r)
                                                        {
                                                            kill_and_reap(pid);
                                                            return Err(format!(
                                                                    "model diff consistency check failed (remove): {}",
                                                                    e
                                                                ));
                                                        }
                                                    }
                                                    for a in &adds {
                                                        if let Err(e) =
                                                            check_model.apply_add(a.clone())
                                                        {
                                                            kill_and_reap(pid);
                                                            return Err(format!(
                                                                    "model diff consistency check failed (add): {}",
                                                                    e
                                                                ));
                                                        }
                                                    }
                                                    if check_model != fresh_maps {
                                                        kill_and_reap(pid);
                                                        return Err(
                                                                "model diff consistency check failed: reconstructed model does not match fresh observed map"
                                                                    .to_string(),
                                                            );
                                                    }

                                                    *cur_model = fresh_maps;
                                                }
                                            }
                                        }
                                    }
                                }
                                None => {
                                    kill_and_reap(pid);
                                    return Err(format!(
                                        "syscall pairing invariant violation for pid {}: received unexpected EXIT (rval={}, is_error={}) with no pending syscall ENTRY",
                                        pid, exit.sval, exit.is_error
                                    ));
                                }
                            }
                        }
                    }
                    libc::PTRACE_SYSCALL_INFO_SECCOMP => {
                        kill_and_reap(pid);
                        return Err(format!(
                            "unsupported seccomp stop for pid {}: nr={}",
                            pid,
                            unsafe { info.u.seccomp.nr }
                        ));
                    }
                    libc::PTRACE_SYSCALL_INFO_NONE => {
                        kill_and_reap(pid);
                        return Err(format!(
                            "tracing invariant violation for pid {}: PTRACE_GET_SYSCALL_INFO returned NONE at syscall stop (status=0x{:x})",
                            pid, status
                        ));
                    }
                    other => {
                        kill_and_reap(pid);
                        return Err(format!(
                            "unexpected ptrace_syscall_info op {} for pid {}",
                            other, pid
                        ));
                    }
                }

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

            let siginfo_res = get_signal_info(pid);

            let info = match siginfo_res {
                Ok(inf) => inf,
                Err(e) => {
                    kill_and_reap(pid);
                    return Err(format!(
                        "pid {}: failed to retrieve siginfo for signal stop {} (possible group-stop or invalid ptrace state): {}",
                        pid, stop_sig, e
                    ));
                }
            };

            if info.si_signo != stop_sig {
                kill_and_reap(pid);
                return Err(format!(
                    "pid {}: siginfo si_signo {} does not match stop signal {}",
                    pid, info.si_signo, stop_sig
                ));
            }

            if let Some(ref mut writer) = trace_writer {
                let unsupported_stopping_signals = [
                    libc::SIGKILL,
                    libc::SIGSTOP,
                    libc::SIGTSTP,
                    libc::SIGTTIN,
                    libc::SIGTTOU,
                    libc::SIGCONT,
                ];
                if unsupported_stopping_signals.contains(&stop_sig) {
                    kill_and_reap(pid);
                    return Err(format!(
                        "pid {}: signal {} is unsupported in M6 deterministic recording",
                        pid, stop_sig
                    ));
                }

                if info.si_code != libc::SI_USER && info.si_code != libc::SI_TKILL {
                    kill_and_reap(pid);
                    return Err(format!(
                        "pid {}: signal {} with unsupported si_code {} is outside M6 supported deterministic class (only SI_USER and SI_TKILL are supported)",
                        pid, stop_sig, info.si_code
                    ));
                }

                if is_bootstrap_exec_exit {
                    kill_and_reap(pid);
                    return Err(format!(
                        "pid {}: signal {} delivered before initial bootstrap MemoryMapSnapshot",
                        pid, stop_sig
                    ));
                }

                let interrupted_subst = pending_syscall
                    .as_ref()
                    .map(|p| p.number)
                    .or(interrupted_syscall)
                    .filter(|&nr| is_substituted_syscall(nr));

                if let Some(nr) = interrupted_subst {
                    kill_and_reap(pid);
                    let name = substituted_syscall_name(nr);
                    return Err(format!(
                        "pid {}: signal {} interposed inside pending {}; signal interposition inside substituted SYS_read/SYS_getpid pairs is outside M6 deterministic replay scope",
                        pid, stop_sig, name
                    ));
                }

                let raw_siginfo: [u8; std::mem::size_of::<libc::siginfo_t>()] =
                    unsafe { std::mem::transmute(info) };

                writer
                    .write_signal_delivery(
                        pid as u32,
                        stop_sig,
                        info.si_errno,
                        info.si_code,
                        &raw_siginfo,
                    )
                    .map_err(|e| {
                        kill_and_reap(pid);
                        format!("failed to write SignalDelivery trace event: {}", e)
                    })?;

                println!(
                    "signal-delivery tid={} sig={} code={} errno={}",
                    pid, stop_sig, info.si_code, info.si_errno
                );

                last_injected_signal = Some(stop_sig);
            }

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

                if err.raw_os_error() != Some(libc::ESRCH) {
                    kill_and_reap(pid);
                    return Err(format!(
                        "PTRACE_SYSCALL reinjecting signal {} failed for pid {}: {}",
                        stop_sig, pid, err
                    ));
                }
            }
            continue;
        }

        kill_and_reap(pid);
        return Err(format!(
            "unexpected wait status 0x{:x} for pid {}: WIFCONTINUED={}",
            status,
            pid,
            libc::WIFCONTINUED(status)
        ));
    }
}
