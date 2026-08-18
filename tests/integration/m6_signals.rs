use causal::maps::MemoryRegion;
use causal::replay::run_replay;
use causal::trace::{
    parse_trace_bytes, read_trace_file_versioned, reconstruct_maps_at_event, TraceEvent,
    TraceWriter, ARCH_X86_64, BYTE_ORDER_LITTLE_ENDIAN, POINTER_WIDTH_64, SIGINFO_SIZE_X86_64,
    SYS_GETPID_X86_64, SYS_MMAP_X86_64, SYS_MPROTECT_X86_64, SYS_READ_X86_64, TRACE_HEADER_MAGIC,
    TRACE_VERSION_4,
};
use causal::tracer::{run_tracee, TraceeTermination};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static TRACE_COUNTER: AtomicU64 = AtomicU64::new(1);
static TIMED_COUNTER: AtomicU64 = AtomicU64::new(1);

fn create_temp_trace_path(label: &str) -> PathBuf {
    let id = TRACE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "causal_m6_{}_{}_{}.causal",
        label,
        std::process::id(),
        id
    ));
    let _ = fs::remove_file(&path);
    path
}

fn get_fixture_path(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin_path = root.join("tests").join("bin").join(name);
    if !bin_path.exists() {
        let script = root.join("scripts").join("build-fixtures.sh");
        let status = Command::new(&script)
            .status()
            .expect("build-fixtures.sh failed");
        assert!(status.success(), "fixture build script failed");
    }
    assert!(bin_path.exists(), "fixture binary missing: {:?}", bin_path);
    bin_path
}

fn causal_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_causal"))
}

fn dummy_stack_region() -> MemoryRegion {
    MemoryRegion {
        start: 0x7fff_0000_0000,
        end: 0x7fff_0001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: b"[stack]".to_vec(),
    }
}

fn dummy_mapped_region() -> MemoryRegion {
    MemoryRegion {
        start: 0x7000_0000_0000,
        end: 0x7000_0001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    }
}

fn create_raw_siginfo(
    sig: i32,
    errno: i32,
    code: i32,
    pid: i32,
    uid: u32,
) -> [u8; SIGINFO_SIZE_X86_64] {
    let mut siginfo = MaybeUninit::<libc::siginfo_t>::zeroed();
    unsafe {
        let ptr = siginfo.as_mut_ptr();
        (*ptr).si_signo = sig;
        (*ptr).si_errno = errno;
        (*ptr).si_code = code;
    }
    let mut raw = [0_u8; SIGINFO_SIZE_X86_64];
    let init = unsafe { siginfo.assume_init() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &init as *const libc::siginfo_t as *const u8,
            raw.as_mut_ptr(),
            std::mem::size_of::<libc::siginfo_t>().min(SIGINFO_SIZE_X86_64),
        );
    }
    raw[16..20].copy_from_slice(&pid.to_le_bytes());
    raw[20..24].copy_from_slice(&uid.to_le_bytes());
    raw
}

// ---------------------------------------------------------------------------
// Process-Group Timeout Harness for Hang-Capable CLI Invocations
// ---------------------------------------------------------------------------

struct TimedChild {
    child: Child,
    pgid: libc::pid_t,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

#[derive(Debug)]
struct TimedCommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
#[allow(dead_code)]
struct TimeoutError {
    pgid: libc::pid_t,
    timeout: Duration,
    stdout: String,
    stderr: String,
}

fn spawn_in_own_process_group(cmd: &mut Command, label: &str) -> TimedChild {
    let id = TIMED_COUNTER.fetch_add(1, Ordering::SeqCst);
    let stdout_path = std::env::temp_dir().join(format!(
        "causal_timed_out_{}_{}_{}.log",
        label,
        std::process::id(),
        id
    ));
    let stderr_path = std::env::temp_dir().join(format!(
        "causal_timed_err_{}_{}_{}.log",
        label,
        std::process::id(),
        id
    ));
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);

    let stdout_file = fs::File::create(&stdout_path).expect("failed to create stdout capture file");
    let stderr_file = fs::File::create(&stderr_path).expect("failed to create stderr capture file");

    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    cmd.stdout(stdout_file);
    cmd.stderr(stderr_file);

    let child = cmd.spawn().expect("failed to spawn timed child");
    let pgid = child.id() as libc::pid_t;

    TimedChild {
        child,
        pgid,
        stdout_path,
        stderr_path,
    }
}

fn wait_with_deadline(
    mut timed: TimedChild,
    timeout: Duration,
) -> Result<TimedCommandOutput, TimeoutError> {
    let start = Instant::now();
    loop {
        match timed.child.try_wait() {
            Ok(Some(status)) => {
                let stdout = fs::read_to_string(&timed.stdout_path).unwrap_or_default();
                let stderr = fs::read_to_string(&timed.stderr_path).unwrap_or_default();
                let _ = fs::remove_file(&timed.stdout_path);
                let _ = fs::remove_file(&timed.stderr_path);
                return Ok(TimedCommandOutput {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let pgid = timed.pgid;
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    let _ = timed.child.wait();

                    let cleanup_deadline = Instant::now() + Duration::from_millis(1000);
                    while Instant::now() < cleanup_deadline {
                        let res = unsafe { libc::kill(-pgid, 0) };
                        if res == -1
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                        {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }

                    let stdout = fs::read_to_string(&timed.stdout_path).unwrap_or_default();
                    let stderr = fs::read_to_string(&timed.stderr_path).unwrap_or_default();
                    let _ = fs::remove_file(&timed.stdout_path);
                    let _ = fs::remove_file(&timed.stderr_path);
                    return Err(TimeoutError {
                        pgid,
                        timeout,
                        stdout,
                        stderr,
                    });
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                panic!("try_wait failed: {}", e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. ABI Size and Codec Tests
// ---------------------------------------------------------------------------

#[test]
fn test_m6_abi_size_proof() {
    assert_eq!(
        std::mem::size_of::<libc::siginfo_t>(),
        SIGINFO_SIZE_X86_64,
        "Linux x86-64 siginfo_t ABI size must be exactly 128 bytes"
    );
}

#[test]
fn test_m6_v4_header_and_signal_delivery_roundtrip() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1234, 1000);

    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    assert_eq!(writer.version(), TRACE_VERSION_4);

    let ev1 = writer
        .write_memory_map_snapshot(1234, std::slice::from_ref(&region))
        .unwrap();
    assert_eq!(ev1, 1);

    let ev2 = writer
        .write_signal_delivery(1234, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    assert_eq!(ev2, 2);

    writer.finish().unwrap();

    assert_eq!(&buf[0..8], TRACE_HEADER_MAGIC);
    assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 4);
    assert_eq!(
        u16::from_le_bytes(buf[12..14].try_into().unwrap()),
        ARCH_X86_64
    );
    assert_eq!(buf[14], BYTE_ORDER_LITTLE_ENDIAN);
    assert_eq!(buf[15], POINTER_WIDTH_64);

    let parsed = parse_trace_bytes(&buf).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);
    assert_eq!(parsed.events.len(), 2);

    match &parsed.events[1] {
        TraceEvent::SignalDelivery {
            event_id,
            tid,
            signal_number,
            si_errno,
            si_code,
            siginfo_bytes,
        } => {
            assert_eq!(*event_id, 2);
            assert_eq!(*tid, 1234);
            assert_eq!(*signal_number, libc::SIGUSR1);
            assert_eq!(*si_errno, 0);
            assert_eq!(*si_code, libc::SI_USER);
            assert_eq!(siginfo_bytes.len(), SIGINFO_SIZE_X86_64);
            assert_eq!(&siginfo_bytes[..], &raw_siginfo[..]);
        }
        other => panic!("expected SignalDelivery, got {:?}", other),
    }
}

#[test]
fn test_m6_v4_deterministic_serialization() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 42, 0);

    let mut buf1 = Vec::new();
    let mut w1 = TraceWriter::new_v4(&mut buf1).unwrap();
    w1.write_memory_map_snapshot(42, std::slice::from_ref(&region))
        .unwrap();
    w1.write_signal_delivery(42, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w1.finish().unwrap();

    let mut buf2 = Vec::new();
    let mut w2 = TraceWriter::new_v4(&mut buf2).unwrap();
    w2.write_memory_map_snapshot(42, std::slice::from_ref(&region))
        .unwrap();
    w2.write_signal_delivery(42, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w2.finish().unwrap();

    assert_eq!(
        buf1, buf2,
        "V4 serialization must be bit-for-bit deterministic"
    );
}

// ---------------------------------------------------------------------------
// 2. Structural Adjacency Tests
// ---------------------------------------------------------------------------

#[test]
fn test_m6_bug_a_signal_breaks_read_memory_write_adjacency_rejected() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    writer
        .write_syscall_enter(1, SYS_READ_X86_64, [0, 0x1000, 10, 0, 0, 0])
        .unwrap();
    let exit_id = writer.write_syscall_exit(1, SYS_READ_X86_64, 5).unwrap();
    writer
        .write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    writer
        .write_kernel_memory_write(1, exit_id, 0x1000, &[1, 2, 3, 4, 5])
        .unwrap();
    writer.finish().unwrap();

    let res = parse_trace_bytes(&buf);
    assert!(
        res.is_err(),
        "must reject SignalDelivery interposed before KernelMemoryWrite"
    );
    let err = res.unwrap_err();
    assert!(
        err.contains("interposes before required KernelMemoryWrite"),
        "expected adjacency error diagnostic: {}",
        err
    );
}

#[test]
fn test_m6_bug_b_signal_breaks_map_delta_adjacency_rejected() {
    let region = dummy_stack_region();
    let map_reg = dummy_mapped_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    // Case 1: SyscallExit(mmap) -> SignalDelivery -> MemoryMapAdd
    let mut buf1 = Vec::new();
    let mut w1 = TraceWriter::new_v4(&mut buf1).unwrap();
    w1.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w1.write_syscall_enter(1, SYS_MMAP_X86_64, [0; 6]).unwrap();
    let exit_id1 = w1
        .write_syscall_exit(1, SYS_MMAP_X86_64, 0x7000_0000_0000)
        .unwrap();
    w1.write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w1.write_memory_map_add(1, exit_id1, &map_reg).unwrap();
    w1.finish().unwrap();

    let res1 = parse_trace_bytes(&buf1);
    assert!(
        res1.is_err(),
        "must reject MemoryMapAdd after SignalDelivery"
    );
    let err1 = res1.unwrap_err();
    assert!(
        err1.contains("is not contiguous with triggering SyscallExit"),
        "expected contiguity error: {}",
        err1
    );

    // Case 2: SyscallExit(mprotect) -> MemoryMapRemove -> SignalDelivery -> MemoryMapAdd
    let mut buf2 = Vec::new();
    let mut w2 = TraceWriter::new_v4(&mut buf2).unwrap();
    w2.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w2.write_syscall_enter(1, SYS_MPROTECT_X86_64, [0; 6])
        .unwrap();
    let exit_id2 = w2.write_syscall_exit(1, SYS_MPROTECT_X86_64, 0).unwrap();
    w2.write_memory_map_remove(1, exit_id2, &region).unwrap();
    w2.write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w2.write_memory_map_add(1, exit_id2, &region).unwrap();
    w2.finish().unwrap();

    let res2 = parse_trace_bytes(&buf2);
    assert!(
        res2.is_err(),
        "must reject MemoryMapAdd split by SignalDelivery"
    );
    let err2 = res2.unwrap_err();
    assert!(
        err2.contains("is not contiguous with triggering SyscallExit"),
        "expected contiguity error: {}",
        err2
    );
}

#[test]
fn test_m6_structural_signal_between_syscall_pair() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    writer.write_syscall_enter(1, 1, [0; 6]).unwrap(); // SYS_write
    writer
        .write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    writer.write_syscall_exit(1, 1, 1234).unwrap();
    writer.finish().unwrap();

    let parsed = parse_trace_bytes(&buf).unwrap();
    assert_eq!(parsed.events.len(), 4);
}

// ---------------------------------------------------------------------------
// 3. Replay Preflight Validation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_m6_replay_preflight_unsupported_signal_rejected_prelaunch() {
    let region = dummy_stack_region();
    let raw_siginfo_stop = create_raw_siginfo(libc::SIGSTOP, 0, libc::SI_USER, 1, 0);

    // 1. Trace with SIGSTOP
    let mut buf1 = Vec::new();
    let mut w1 = TraceWriter::new_v4(&mut buf1).unwrap();
    w1.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w1.write_signal_delivery(1, libc::SIGSTOP, 0, libc::SI_USER, &raw_siginfo_stop)
        .unwrap();
    w1.finish().unwrap();

    let trace_path1 = create_temp_trace_path("preflight_stop");
    fs::write(&trace_path1, &buf1).unwrap();

    let res1 = run_replay(&trace_path1, "/nonexistent/path/that/cannot/launch", &[]);
    assert!(res1.is_err(), "must reject unsupported signal prelaunch");
    let err1 = res1.unwrap_err();
    assert!(
        err1.contains("is unsupported in M6 deterministic replay"),
        "expected preflight error: {}",
        err1
    );

    // 2. Trace with unsupported si_code (e.g. 123)
    let raw_siginfo_code = create_raw_siginfo(libc::SIGUSR1, 0, 123, 1, 0);
    let mut buf2 = Vec::new();
    let mut w2 = TraceWriter::new_v4(&mut buf2).unwrap();
    w2.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w2.write_signal_delivery(1, libc::SIGUSR1, 0, 123, &raw_siginfo_code)
        .unwrap();
    w2.finish().unwrap();

    let trace_path2 = create_temp_trace_path("preflight_code");
    fs::write(&trace_path2, &buf2).unwrap();

    let res2 = run_replay(&trace_path2, "/nonexistent/path/that/cannot/launch", &[]);
    assert!(res2.is_err(), "must reject unsupported si_code prelaunch");
    let err2 = res2.unwrap_err();
    assert!(
        err2.contains("outside M6 supported deterministic class"),
        "expected preflight error: {}",
        err2
    );

    let _ = fs::remove_file(&trace_path1);
    let _ = fs::remove_file(&trace_path2);
}

#[test]
fn test_m6_replay_preflight_signal_interposed_in_substituted_syscall_rejected() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    // Case 1: Interposed inside SYS_getpid
    let mut buf1 = Vec::new();
    let mut w1 = TraceWriter::new_v4(&mut buf1).unwrap();
    w1.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w1.write_syscall_enter(1, SYS_GETPID_X86_64, [0; 6])
        .unwrap();
    w1.write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w1.write_syscall_exit(1, SYS_GETPID_X86_64, 42).unwrap();
    w1.finish().unwrap();

    let trace_path1 = create_temp_trace_path("preflight_interposed_getpid");
    fs::write(&trace_path1, &buf1).unwrap();

    let res1 = run_replay(&trace_path1, "/nonexistent/path/that/cannot/launch", &[]);
    assert!(
        res1.is_err(),
        "must reject interposed signal inside substituted SYS_getpid prelaunch"
    );
    let err1 = res1.unwrap_err();
    assert!(
        err1.contains("SignalDelivery interposed inside substituted SYS_getpid pair"),
        "expected SYS_getpid preflight error: {}",
        err1
    );

    // Case 2: Interposed inside SYS_read (result 0 so no KernelMemoryWrite needed)
    let mut buf2 = Vec::new();
    let mut w2 = TraceWriter::new_v4(&mut buf2).unwrap();
    w2.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w2.write_syscall_enter(1, SYS_READ_X86_64, [0, 0x1000, 10, 0, 0, 0])
        .unwrap();
    w2.write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w2.write_syscall_exit(1, SYS_READ_X86_64, 0).unwrap();
    w2.finish().unwrap();

    let trace_path2 = create_temp_trace_path("preflight_interposed_read");
    fs::write(&trace_path2, &buf2).unwrap();

    let res2 = run_replay(&trace_path2, "/nonexistent/path/that/cannot/launch", &[]);
    assert!(
        res2.is_err(),
        "must reject interposed signal inside substituted SYS_read prelaunch"
    );
    let err2 = res2.unwrap_err();
    assert!(
        err2.contains("SignalDelivery interposed inside substituted SYS_read pair"),
        "expected SYS_read preflight error: {}",
        err2
    );

    let _ = fs::remove_file(&trace_path1);
    let _ = fs::remove_file(&trace_path2);
}

// ---------------------------------------------------------------------------
// 4. Parser-Level Corruption Tests with Diagnostic Substring Proofs
// ---------------------------------------------------------------------------

fn create_raw_signal_trace_v(version: u32) -> Vec<u8> {
    let raw_sig = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(TRACE_HEADER_MAGIC);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&ARCH_X86_64.to_le_bytes());
    bytes.push(BYTE_ORDER_LITTLE_ENDIAN);
    bytes.push(POINTER_WIDTH_64);

    // Record length: 32 + 128 = 160
    bytes.extend_from_slice(&160_u32.to_le_bytes());
    bytes.push(7); // kind = 7 (SignalDelivery)
    bytes.extend_from_slice(&[0_u8; 3]);
    bytes.extend_from_slice(&1_u64.to_le_bytes()); // event_id = 1
    bytes.extend_from_slice(&1_u32.to_le_bytes()); // tid = 1
    bytes.extend_from_slice(&libc::SIGUSR1.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&libc::SI_USER.to_le_bytes());
    bytes.extend_from_slice(&128_u32.to_le_bytes());
    bytes.extend_from_slice(&raw_sig);

    // Footer: event_count = 1, magic = CAUSEND\0
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(b"CAUSEND\0");
    bytes
}

#[test]
fn test_m6_old_version_kind_7_parser_rejections() {
    // V1 with raw kind 7
    let v1 = create_raw_signal_trace_v(1);
    let err1 = parse_trace_bytes(&v1).unwrap_err();
    assert!(
        err1.contains("SignalDelivery event kind 7 is not supported in trace format V1"),
        "expected V1 kind 7 diagnostic: {}",
        err1
    );

    // V2 with raw kind 7
    let v2 = create_raw_signal_trace_v(2);
    let err2 = parse_trace_bytes(&v2).unwrap_err();
    assert!(
        err2.contains("SignalDelivery event kind 7 is not supported in trace format V2"),
        "expected V2 kind 7 diagnostic: {}",
        err2
    );

    // V3 with raw kind 7
    let v3 = create_raw_signal_trace_v(3);
    let err3 = parse_trace_bytes(&v3).unwrap_err();
    assert!(
        err3.contains("SignalDelivery event kind 7 is not supported in trace format V3"),
        "expected V3 kind 7 diagnostic: {}",
        err3
    );
}

#[test]
fn test_m6_truncated_siginfo_boundary_parser_rejection() {
    let region = dummy_stack_region();
    let raw_sig = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    // Valid V4 header + Snapshot + SignalDelivery declaring 160 bytes but physically giving only 50 bytes + Valid Footer
    let mut bytes = Vec::new();
    let mut w = TraceWriter::new_v4(&mut bytes).unwrap();
    w.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w.finish().unwrap();

    // Strip the footer (last 16 bytes)
    let footer = bytes.split_off(bytes.len() - 16);

    // Append SignalDelivery with declared length 160 but only 50 physical bytes before the valid footer
    bytes.extend_from_slice(&160_u32.to_le_bytes()); // Declared record length 160
    bytes.push(7); // kind = 7
    bytes.extend_from_slice(&[0_u8; 3]);
    bytes.extend_from_slice(&2_u64.to_le_bytes()); // event_id = 2
    bytes.extend_from_slice(&1_u32.to_le_bytes()); // tid = 1
    bytes.extend_from_slice(&libc::SIGUSR1.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&libc::SI_USER.to_le_bytes());
    bytes.extend_from_slice(&128_u32.to_le_bytes());
    bytes.extend_from_slice(&raw_sig[..18]); // Only 18 bytes of siginfo (total body = 50 bytes)

    // Append valid footer declaring event_count = 2
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    bytes.extend_from_slice(&footer[8..16]); // CAUSEND\0

    let err = parse_trace_bytes(&bytes).unwrap_err();
    assert!(
        err.contains("record length 160 extends past event data region into footer"),
        "expected boundary diagnostic: {}",
        err
    );
}

#[test]
fn test_m6_corruption_diagnostic_reasons() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    let mut valid_v4 = Vec::new();
    let mut w = TraceWriter::new_v4(&mut valid_v4).unwrap();
    w.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w.write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w.finish().unwrap();

    let sig_rec_offset = 16 + 4 + u32::from_le_bytes(valid_v4[16..20].try_into().unwrap()) as usize;

    // 1. signal_number = 0
    let mut bad_sig0 = valid_v4.clone();
    bad_sig0[sig_rec_offset + 4 + 16..sig_rec_offset + 4 + 20]
        .copy_from_slice(&0_i32.to_le_bytes());
    let err0 = parse_trace_bytes(&bad_sig0).unwrap_err();
    assert!(
        err0.contains("invalid signal number 0"),
        "expected signal 0 diagnostic: {}",
        err0
    );

    // 2. signal_number > 64 (65)
    let mut bad_sig65 = valid_v4.clone();
    bad_sig65[sig_rec_offset + 4 + 16..sig_rec_offset + 4 + 20]
        .copy_from_slice(&65_i32.to_le_bytes());
    let err65 = parse_trace_bytes(&bad_sig65).unwrap_err();
    assert!(
        err65.contains("invalid signal number 65"),
        "expected signal 65 diagnostic: {}",
        err65
    );

    // 3. Short record length (< 32)
    let mut short_hdr = valid_v4.clone();
    short_hdr[sig_rec_offset..sig_rec_offset + 4].copy_from_slice(&20_u32.to_le_bytes());
    let err_short_hdr = parse_trace_bytes(&short_hdr).unwrap_err();
    assert!(
        err_short_hdr.contains("smaller than minimum header 32"),
        "expected short header diagnostic: {}",
        err_short_hdr
    );

    // 4. siginfo_len < 128 (64)
    let mut bad_len_short = valid_v4.clone();
    bad_len_short[sig_rec_offset + 4 + 28..sig_rec_offset + 4 + 32]
        .copy_from_slice(&64_u32.to_le_bytes());
    let err_short_len = parse_trace_bytes(&bad_len_short).unwrap_err();
    assert!(
        err_short_len.contains("invalid siginfo_len 64, expected 128"),
        "expected short siginfo_len diagnostic: {}",
        err_short_len
    );

    // 5. siginfo_len > 128 (256)
    let mut bad_len_long = valid_v4.clone();
    bad_len_long[sig_rec_offset + 4 + 28..sig_rec_offset + 4 + 32]
        .copy_from_slice(&256_u32.to_le_bytes());
    let err_long_len = parse_trace_bytes(&bad_len_long).unwrap_err();
    assert!(
        err_long_len.contains("invalid siginfo_len 256, expected 128"),
        "expected long siginfo_len diagnostic: {}",
        err_long_len
    );

    // 6. record_length / siginfo_len mismatch
    let mut bad_rec_len = valid_v4.clone();
    bad_rec_len[sig_rec_offset..sig_rec_offset + 4].copy_from_slice(&150_u32.to_le_bytes());
    let err_rec_mismatch = parse_trace_bytes(&bad_rec_len).unwrap_err();
    assert!(
        err_rec_mismatch.contains("record length 150 does not match 32 + siginfo_len (128)"),
        "expected length mismatch diagnostic: {}",
        err_rec_mismatch
    );

    // 7. Raw si_signo mismatch
    let mut bad_raw_signo = valid_v4.clone();
    bad_raw_signo[sig_rec_offset + 4 + 32..sig_rec_offset + 4 + 36]
        .copy_from_slice(&libc::SIGTERM.to_le_bytes());
    let err_raw_signo = parse_trace_bytes(&bad_raw_signo).unwrap_err();
    assert!(
        err_raw_signo.contains("raw siginfo si_signo 15 does not match explicit signal_number 10"),
        "expected raw si_signo mismatch diagnostic: {}",
        err_raw_signo
    );

    // 8. Raw si_errno mismatch
    let mut bad_raw_errno = valid_v4.clone();
    bad_raw_errno[sig_rec_offset + 4 + 36..sig_rec_offset + 4 + 40]
        .copy_from_slice(&99_i32.to_le_bytes());
    let err_raw_errno = parse_trace_bytes(&bad_raw_errno).unwrap_err();
    assert!(
        err_raw_errno.contains("raw siginfo si_errno 99 does not match explicit si_errno 0"),
        "expected raw si_errno mismatch diagnostic: {}",
        err_raw_errno
    );

    // 9. Raw si_code mismatch
    let mut bad_raw_code = valid_v4.clone();
    bad_raw_code[sig_rec_offset + 4 + 40..sig_rec_offset + 4 + 44]
        .copy_from_slice(&99_i32.to_le_bytes());
    let err_raw_code = parse_trace_bytes(&bad_raw_code).unwrap_err();
    assert!(
        err_raw_code.contains("raw siginfo si_code 99 does not match explicit si_code 0"),
        "expected raw si_code mismatch diagnostic: {}",
        err_raw_code
    );

    // 10. Unknown V4 event kind (kind 8)
    let mut unknown_kind = valid_v4.clone();
    unknown_kind[sig_rec_offset + 4] = 8;
    let err_unknown = parse_trace_bytes(&unknown_kind).unwrap_err();
    assert!(
        err_unknown.contains("unknown event kind 8"),
        "expected unknown kind diagnostic: {}",
        err_unknown
    );

    // 11. SignalDelivery before required MemoryMapSnapshot in V4
    let raw_sig = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);
    let mut manual_v4 = Vec::new();
    manual_v4.extend_from_slice(TRACE_HEADER_MAGIC);
    manual_v4.extend_from_slice(&4_u32.to_le_bytes());
    manual_v4.extend_from_slice(&ARCH_X86_64.to_le_bytes());
    manual_v4.push(BYTE_ORDER_LITTLE_ENDIAN);
    manual_v4.push(POINTER_WIDTH_64);
    manual_v4.extend_from_slice(&160_u32.to_le_bytes());
    manual_v4.push(7);
    manual_v4.extend_from_slice(&[0_u8; 3]);
    manual_v4.extend_from_slice(&1_u64.to_le_bytes());
    manual_v4.extend_from_slice(&1_u32.to_le_bytes());
    manual_v4.extend_from_slice(&libc::SIGUSR1.to_le_bytes());
    manual_v4.extend_from_slice(&0_i32.to_le_bytes());
    manual_v4.extend_from_slice(&libc::SI_USER.to_le_bytes());
    manual_v4.extend_from_slice(&128_u32.to_le_bytes());
    manual_v4.extend_from_slice(&raw_sig);
    manual_v4.extend_from_slice(&1_u64.to_le_bytes());
    manual_v4.extend_from_slice(b"CAUSEND\0");
    let err_no_snap = parse_trace_bytes(&manual_v4).unwrap_err();
    assert!(
        err_no_snap.contains("missing initial MemoryMapSnapshot before SignalDelivery event 1"),
        "expected missing snapshot diagnostic: {}",
        err_no_snap
    );
}

// ---------------------------------------------------------------------------
// 5. Timeout Harness Self-Test (Intentional Hang Cleanup Proof)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_timeout_harness_kills_stuck_process_group() {
    let fixture = get_fixture_path("signal_external_term");
    let trace_path = create_temp_trace_path("timeout_hang");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_hang_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let mut cmd = Command::new(causal_binary());
    cmd.arg("record")
        .arg("-o")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&ready_file);

    let timed_child = spawn_in_own_process_group(&mut cmd, "hang_test");
    let pgid = timed_child.pgid;

    // Wait until fixture writes PID, then DO NOT send SIGTERM
    let mut target_pid: Option<i32> = None;
    let poll_start = Instant::now();
    while poll_start.elapsed() < Duration::from_secs(3) {
        if let Ok(content) = fs::read_to_string(&ready_file) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                target_pid = Some(pid);
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    let target_pid = target_pid.expect("target failed to write ready file");

    // Call wait_with_deadline with a short deadline (500ms)
    let res = wait_with_deadline(timed_child, Duration::from_millis(500));
    assert!(res.is_err(), "must report timeout error");

    // Verify tracee PID returned ESRCH to kill(pid, 0)
    let tracee_alive = unsafe { libc::kill(target_pid, 0) };
    assert_eq!(tracee_alive, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "tracee must be destroyed"
    );

    // Verify process group returned ESRCH
    let pg_alive = unsafe { libc::kill(-pgid, 0) };
    assert_eq!(pg_alive, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "process group must be destroyed"
    );

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
}

// ---------------------------------------------------------------------------
// 6. Flagship External SIGUSR1 Recording & Replay Proof (Timed Subprocess)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_external_sigusr1_recording_and_replay() {
    let fixture = get_fixture_path("signal_external_usr1");
    let trace_path = create_temp_trace_path("usr1_flagship");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_usr1_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let sender_pid = std::process::id() as i32;

    // 1. Spawning timed CAUSAL record subprocess
    let mut rec_cmd = Command::new(causal_binary());
    rec_cmd
        .arg("record")
        .arg("-o")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&ready_file)
        .env("CAUSAL_EXPECT_SIGNAL_SENDER_PID", sender_pid.to_string())
        .env("CAUSAL_EXPECT_SIGNAL_CODE", libc::SI_USER.to_string());

    let rec_child = spawn_in_own_process_group(&mut rec_cmd, "usr1_rec");

    // Sender thread sends SIGUSR1 once ready
    let ready_clone = ready_file.clone();
    let sender_thread = thread::spawn(move || {
        let start = Instant::now();
        let mut target_pid: Option<i32> = None;
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(content) = fs::read_to_string(&ready_clone) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    target_pid = Some(pid);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let pid = target_pid.expect("target failed to write readiness file within 5s");
        thread::sleep(Duration::from_millis(20));

        let res = unsafe { libc::kill(pid, libc::SIGUSR1) };
        assert_eq!(res, 0, "failed to send SIGUSR1 to target");
    });

    let rec_out = wait_with_deadline(rec_child, Duration::from_secs(10))
        .expect("recording timed out or failed");
    sender_thread.join().unwrap();
    assert!(
        rec_out.status.success(),
        "record command failed: {:?}",
        rec_out
    );

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);

    let sig_event = parsed
        .events
        .iter()
        .find(|e| matches!(e, TraceEvent::SignalDelivery { .. }))
        .expect("SignalDelivery event missing from recorded trace");

    match sig_event {
        TraceEvent::SignalDelivery {
            signal_number,
            si_code,
            siginfo_bytes,
            ..
        } => {
            assert_eq!(*signal_number, libc::SIGUSR1);
            assert_eq!(*si_code, libc::SI_USER);
            assert_eq!(siginfo_bytes.len(), SIGINFO_SIZE_X86_64);
            let recorded_sender = i32::from_le_bytes(siginfo_bytes[16..20].try_into().unwrap());
            assert_eq!(recorded_sender, sender_pid);
        }
        _ => unreachable!(),
    }

    let _ = fs::remove_file(&ready_file);

    // 2. REPLAY PROOF: Replay with ABSOLUTELY NO external sender thread/signal!
    let replay_ready = std::env::temp_dir().join(format!(
        "causal_replay_ready_usr1_{}.pid",
        std::process::id()
    ));
    let _ = fs::remove_file(&replay_ready);

    let mut rep_cmd = Command::new(causal_binary());
    rep_cmd
        .arg("replay")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&replay_ready)
        .env("CAUSAL_EXPECT_SIGNAL_SENDER_PID", sender_pid.to_string())
        .env("CAUSAL_EXPECT_SIGNAL_CODE", libc::SI_USER.to_string());

    let rep_child = spawn_in_own_process_group(&mut rep_cmd, "usr1_rep");
    let rep_out =
        wait_with_deadline(rep_child, Duration::from_secs(10)).expect("replay timed out or failed");
    assert!(
        rep_out.status.success(),
        "replay command failed: {:?}",
        rep_out
    );

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&replay_ready);
}

// ---------------------------------------------------------------------------
// 7. Default-Action SIGTERM Termination Proof (Timed Subprocess)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_external_sigterm_default_action_record_and_replay() {
    let fixture = get_fixture_path("signal_external_term");
    let trace_path = create_temp_trace_path("term_default");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_term_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    // 1. Recording timed subprocess
    let mut rec_cmd = Command::new(causal_binary());
    rec_cmd
        .arg("record")
        .arg("-o")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&ready_file);

    let rec_child = spawn_in_own_process_group(&mut rec_cmd, "term_rec");

    let ready_clone = ready_file.clone();
    let sender_thread = thread::spawn(move || {
        let start = Instant::now();
        let mut target_pid: Option<i32> = None;
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(content) = fs::read_to_string(&ready_clone) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    target_pid = Some(pid);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let pid = target_pid.expect("target failed to write readiness file within 5s");
        thread::sleep(Duration::from_millis(20));

        let res = unsafe { libc::kill(pid, libc::SIGTERM) };
        assert_eq!(res, 0, "failed to send SIGTERM");
    });

    let rec_out = wait_with_deadline(rec_child, Duration::from_secs(10))
        .expect("recording timed out or failed");
    sender_thread.join().unwrap();
    assert_eq!(rec_out.status.code(), Some(128 + libc::SIGTERM));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);

    let has_sigterm = parsed.events.iter().any(|e| match e {
        TraceEvent::SignalDelivery { signal_number, .. } => *signal_number == libc::SIGTERM,
        _ => false,
    });
    assert!(has_sigterm, "trace must contain SignalDelivery(SIGTERM)");

    // 2. Replay with NO external signal sender
    let replay_ready = std::env::temp_dir().join(format!(
        "causal_replay_ready_term_{}.pid",
        std::process::id()
    ));
    let _ = fs::remove_file(&replay_ready);

    let mut rep_cmd = Command::new(causal_binary());
    rep_cmd
        .arg("replay")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&replay_ready);

    let rep_child = spawn_in_own_process_group(&mut rep_cmd, "term_rep");
    let rep_out =
        wait_with_deadline(rep_child, Duration::from_secs(10)).expect("replay timed out or failed");

    // Exit code must be 128 + 15 = 143
    assert_eq!(rep_out.status.code(), Some(128 + libc::SIGTERM));

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&replay_ready);
}

// ---------------------------------------------------------------------------
// 8. Live Blocked SYS_read Signal Interposition Rejection Proof
// ---------------------------------------------------------------------------

#[test]
fn test_m6_signal_during_read_unsupported_rejected_record() {
    let fixture = get_fixture_path("signal_during_read_unsupported");
    let trace_path = create_temp_trace_path("signal_during_read");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_read_int_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let mut cmd = Command::new(causal_binary());
    cmd.arg("record")
        .arg("-o")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&ready_file);

    let child = spawn_in_own_process_group(&mut cmd, "read_int_rec");

    let ready_clone = ready_file.clone();
    let sender_thread = thread::spawn(move || {
        let start = Instant::now();
        let mut target_pid: Option<i32> = None;
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(content) = fs::read_to_string(&ready_clone) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    target_pid = Some(pid);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let pid = target_pid.expect("target failed to write readiness file within 5s");
        thread::sleep(Duration::from_millis(30)); // Ensure target entered blocking SYS_read

        let res = unsafe { libc::kill(pid, libc::SIGUSR1) };
        assert_eq!(res, 0, "failed to send SIGUSR1 to target blocked on read");
        pid
    });

    let out = wait_with_deadline(child, Duration::from_secs(10))
        .expect("recording timed out or hung unexpectedly");
    let target_pid = sender_thread.join().unwrap();

    // Must fail recording
    assert!(
        !out.status.success(),
        "record must fail when signal interposes inside SYS_read"
    );

    // Stderr or stdout must contain specific diagnostic
    let combined_out = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        combined_out.contains("signal 10 interposed inside pending SYS_read"),
        "expected interposition diagnostic in output: {}",
        combined_out
    );
    assert!(
        combined_out.contains("outside M6 deterministic replay scope"),
        "expected scope diagnostic in output: {}",
        combined_out
    );

    // Incomplete trace must be removed
    assert!(
        !trace_path.exists(),
        "incomplete trace file must be removed on failure"
    );

    // Target process must be reaped
    let tracee_alive = unsafe { libc::kill(target_pid, 0) };
    assert_eq!(tracee_alive, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "tracee must be reaped"
    );

    let _ = fs::remove_file(&ready_file);
}

// ---------------------------------------------------------------------------
// 9. Multiple Signals & Interleaved Execution
// ---------------------------------------------------------------------------

#[test]
fn test_m6_multiple_supported_signals_roundtrip() {
    let fixture = get_fixture_path("signal_multi_usr");
    let trace_path = create_temp_trace_path("multi_usr");

    let rec_res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(rec_res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);

    let sig_events: Vec<_> = parsed
        .events
        .iter()
        .filter(|e| matches!(e, TraceEvent::SignalDelivery { .. }))
        .collect();
    assert_eq!(sig_events.len(), 2, "must record both SIGUSR1 and SIGUSR2");

    let replay_res = run_replay(&trace_path, fixture.to_str().unwrap(), &[]);
    assert_eq!(replay_res, Ok(TraceeTermination::Exited(0)));

    let _ = fs::remove_file(&trace_path);
}

// ---------------------------------------------------------------------------
// 10. Unsupported Signals & Fault Rejection (Timed Subprocesses)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_unsupported_stopping_signal_rejected() {
    let fixture = get_fixture_path("signal_stop_unsupported");
    let trace_path = create_temp_trace_path("stop_unsupported");

    let mut cmd = Command::new(causal_binary());
    cmd.arg("record").arg("-o").arg(&trace_path).arg(&fixture);

    let child = spawn_in_own_process_group(&mut cmd, "stop_unsupported");
    let out =
        wait_with_deadline(child, Duration::from_secs(10)).expect("SIGSTOP test timed out or hung");

    assert!(!out.status.success(), "recording SIGSTOP must fail");
    let combined_out = format!("{}\n{}", out.stdout, out.stderr);
    assert!(
        combined_out.contains("is unsupported in M6 deterministic recording"),
        "expected unsupported diagnostic: {}",
        combined_out
    );

    assert!(
        !trace_path.exists(),
        "incomplete trace must be removed on failure"
    );
}

#[test]
fn test_m6_unsupported_synchronous_fault_rejected() {
    let fixture = get_fixture_path("signal_segv_unsupported");
    let trace_path = create_temp_trace_path("segv_unsupported");

    let rec_res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert!(rec_res.is_err(), "recording synchronous SIGSEGV must fail");
    let err = rec_res.unwrap_err();
    assert!(
        err.contains("outside M6 supported deterministic class"),
        "expected unsupported class diagnostic: {}",
        err
    );

    assert!(
        !trace_path.exists(),
        "incomplete trace must be removed on failure"
    );
}

// ---------------------------------------------------------------------------
// 11. SIGTRAP Classification
// ---------------------------------------------------------------------------

#[test]
fn test_m6_sigtrap_classification() {
    let fixture = get_fixture_path("raise_sigtrap");
    let trace_path = create_temp_trace_path("sigtrap");

    let rec_res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(rec_res, Ok(TraceeTermination::Signaled(libc::SIGTRAP)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    let sigtrap_ev = parsed.events.iter().find(|e| match e {
        TraceEvent::SignalDelivery { signal_number, .. } => *signal_number == libc::SIGTRAP,
        _ => false,
    });
    assert!(
        sigtrap_ev.is_some(),
        "plain SIGTRAP must be classified as SignalDelivery"
    );

    let replay_res = run_replay(&trace_path, fixture.to_str().unwrap(), &[]);
    assert_eq!(replay_res, Ok(TraceeTermination::Signaled(libc::SIGTRAP)));

    let _ = fs::remove_file(&trace_path);
}

// ---------------------------------------------------------------------------
// 12. Replay Divergence on Unrecorded Live Signal (Timed Subprocess)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_replay_divergence_unrecorded_live_signal() {
    let fixture = get_fixture_path("signal_external_usr1");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_diverge_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let region = dummy_stack_region();

    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    writer
        .write_syscall_enter(1, SYS_GETPID_X86_64, [0; 6])
        .unwrap();
    writer
        .write_syscall_exit(1, SYS_GETPID_X86_64, 100)
        .unwrap();
    writer.finish().unwrap();

    let trace_path = create_temp_trace_path("unrecorded_diverge");
    fs::write(&trace_path, &buf).unwrap();

    let mut rep_cmd = Command::new(causal_binary());
    rep_cmd
        .arg("replay")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&ready_file);

    let rep_child = spawn_in_own_process_group(&mut rep_cmd, "diverge_rep");

    let ready_clone = ready_file.clone();
    let sender_thread = thread::spawn(move || {
        let start = Instant::now();
        let mut target_pid: Option<i32> = None;
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(content) = fs::read_to_string(&ready_clone) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    target_pid = Some(pid);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        if let Some(pid) = target_pid {
            thread::sleep(Duration::from_millis(20));
            unsafe { libc::kill(pid, libc::SIGUSR1) };
        }
    });

    let rep_out = wait_with_deadline(rep_child, Duration::from_secs(10))
        .expect("divergence replay timed out");
    sender_thread.join().unwrap();

    assert!(
        !rep_out.status.success(),
        "replay with unrecorded signal must fail"
    );
    let combined_out = format!("{}\n{}", rep_out.stdout, rep_out.stderr);
    assert!(
        combined_out.contains("divergence"),
        "expected divergence diagnostic in output: {}",
        combined_out
    );

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
}

// ---------------------------------------------------------------------------
// 13. Historical Maps Query Support
// ---------------------------------------------------------------------------

#[test]
fn test_m6_v4_historical_maps_query() {
    let fixture = get_fixture_path("map_model");
    let trace_path = create_temp_trace_path("v4_maps");

    let rec_res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(rec_res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);

    let model_at_1 = reconstruct_maps_at_event(&parsed, 1).unwrap();
    assert!(!model_at_1.regions().is_empty());

    let cli_out = Command::new(causal_binary())
        .arg("maps")
        .arg(&trace_path)
        .arg("1")
        .output()
        .unwrap();
    assert!(cli_out.status.success());
    let stdout = String::from_utf8_lossy(&cli_out.stdout);
    assert!(!stdout.is_empty());

    let _ = fs::remove_file(&trace_path);
}

// ---------------------------------------------------------------------------
// 14. Flagship 100-Replay Stress Test with Per-Iteration Process Deadlines
// ---------------------------------------------------------------------------

#[test]
fn test_m6_100_replays_stress() {
    let fixture = get_fixture_path("signal_external_usr1");
    let trace_path = create_temp_trace_path("usr1_100_stress");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_stress_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let sender_pid = std::process::id() as i32;

    // 1. Record once with external signal
    let mut rec_cmd = Command::new(causal_binary());
    rec_cmd
        .arg("record")
        .arg("-o")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&ready_file)
        .env("CAUSAL_EXPECT_SIGNAL_SENDER_PID", sender_pid.to_string())
        .env("CAUSAL_EXPECT_SIGNAL_CODE", libc::SI_USER.to_string());

    let rec_child = spawn_in_own_process_group(&mut rec_cmd, "stress_rec");

    let ready_clone = ready_file.clone();
    let sender_thread = thread::spawn(move || {
        let start = Instant::now();
        let mut target_pid: Option<i32> = None;
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(content) = fs::read_to_string(&ready_clone) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    target_pid = Some(pid);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        let pid = target_pid.expect("target failed to write readiness file within 5s");
        thread::sleep(Duration::from_millis(20));

        let res = unsafe { libc::kill(pid, libc::SIGUSR1) };
        assert_eq!(res, 0, "failed to send SIGUSR1");
    });

    let rec_out = wait_with_deadline(rec_child, Duration::from_secs(10))
        .expect("recording timed out in 100-replay test");
    sender_thread.join().unwrap();
    assert!(rec_out.status.success(), "record failed: {:?}", rec_out);

    let _ = fs::remove_file(&ready_file);

    // 2. Replay 100 times in isolated process groups with per-iteration deadlines and ZERO external signals
    for i in 1..=100 {
        let replay_ready = std::env::temp_dir().join(format!(
            "causal_replay_stress_{}_{}.pid",
            std::process::id(),
            i
        ));
        let _ = fs::remove_file(&replay_ready);

        let mut rep_cmd = Command::new(causal_binary());
        rep_cmd
            .arg("replay")
            .arg(&trace_path)
            .arg(&fixture)
            .arg(&replay_ready)
            .env("CAUSAL_EXPECT_SIGNAL_SENDER_PID", sender_pid.to_string())
            .env("CAUSAL_EXPECT_SIGNAL_CODE", libc::SI_USER.to_string());

        let rep_child = spawn_in_own_process_group(&mut rep_cmd, "stress_rep_iter");
        let rep_out = match wait_with_deadline(rep_child, Duration::from_secs(5)) {
            Ok(o) => o,
            Err(e) => {
                panic!("Iteration {} timed out after 5s: {:?}", i, e);
            }
        };

        assert!(
            rep_out.status.success(),
            "Replay iteration {} failed with status {:?}, stderr: {}",
            i,
            rep_out.status,
            rep_out.stderr
        );

        let _ = fs::remove_file(&replay_ready);
    }

    let _ = fs::remove_file(&trace_path);
}
