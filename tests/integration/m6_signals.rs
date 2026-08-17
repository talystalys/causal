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
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static TRACE_COUNTER: AtomicU64 = AtomicU64::new(1);

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
    // Set si_pid at bytes 16..20 and si_uid at bytes 20..24
    raw[16..20].copy_from_slice(&pid.to_le_bytes());
    raw[20..24].copy_from_slice(&uid.to_le_bytes());
    raw
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
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 100, 1000);

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

    // Check header
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
// 2. Structural Adjacency Tests (Bug A and Bug B Closures)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_bug_a_signal_breaks_read_memory_write_adjacency_rejected() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    // Malformed sequence:
    // MemoryMapSnapshot
    // SyscallEnter(SYS_read, count = 10, buf = 0x1000)
    // SyscallExit(SYS_read, result = 5)
    // SignalDelivery(SIGUSR1) <--- INVALID INTERPOSITION
    // KernelMemoryWrite(source = SyscallExit)
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
    // Valid structural sequence:
    // MemoryMapSnapshot
    // SyscallEnter(SYS_getpid)
    // SignalDelivery(SIGUSR1)
    // SyscallExit(SYS_getpid)
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    writer.write_syscall_enter(1, 39, [0; 6]).unwrap();
    writer
        .write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    writer.write_syscall_exit(1, 39, 1234).unwrap();
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

    // Use nonexistent binary path as target to prove replay rejects BEFORE launch
    let res1 = run_replay(&trace_path1, "/nonexistent/path/that/cannot/launch", &[]);
    assert!(res1.is_err(), "must reject unsupported signal prelaunch");
    let err1 = res1.unwrap_err();
    assert!(
        err1.contains("is unsupported in M6 deterministic replay"),
        "expected preflight error: {}",
        err1
    );

    // 2. Trace with unsupported si_code (e.g. SI_KERNEL = 0x80)
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

    // Trace with SignalDelivery interposed inside SYS_getpid
    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    writer
        .write_syscall_enter(1, SYS_GETPID_X86_64, [0; 6])
        .unwrap();
    writer
        .write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    writer.write_syscall_exit(1, SYS_GETPID_X86_64, 42).unwrap();
    writer.finish().unwrap();

    let trace_path = create_temp_trace_path("preflight_interposed");
    fs::write(&trace_path, &buf).unwrap();

    let res = run_replay(&trace_path, "/nonexistent/path/that/cannot/launch", &[]);
    assert!(
        res.is_err(),
        "must reject interposed signal inside substituted syscall prelaunch"
    );
    let err = res.unwrap_err();
    assert!(
        err.contains("SignalDelivery interposed inside substituted SYS_getpid pair"),
        "expected preflight error: {}",
        err
    );

    let _ = fs::remove_file(&trace_path);
}

// ---------------------------------------------------------------------------
// 4. Comprehensive Parser-Level V4 Corruption Coverage
// ---------------------------------------------------------------------------

#[test]
fn test_m6_parser_level_corruption_cases() {
    let region = dummy_stack_region();
    let raw_siginfo = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);

    // Build valid V4 trace bytes as baseline
    let mut valid_v4 = Vec::new();
    let mut w = TraceWriter::new_v4(&mut valid_v4).unwrap();
    w.write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    w.write_signal_delivery(1, libc::SIGUSR1, 0, libc::SI_USER, &raw_siginfo)
        .unwrap();
    w.finish().unwrap();

    // 1. SignalDelivery raw kind 7 in V1 file
    let mut v1_file = valid_v4.clone();
    v1_file[8..12].copy_from_slice(&1_u32.to_le_bytes()); // version = 1
    assert!(parse_trace_bytes(&v1_file).is_err());

    // 2. SignalDelivery raw kind 7 in V2 file
    let mut v2_file = valid_v4.clone();
    v2_file[8..12].copy_from_slice(&2_u32.to_le_bytes()); // version = 2
    assert!(parse_trace_bytes(&v2_file).is_err());

    // 3. SignalDelivery raw kind 7 in V3 file
    let mut v3_file = valid_v4.clone();
    v3_file[8..12].copy_from_slice(&3_u32.to_le_bytes()); // version = 3
    assert!(parse_trace_bytes(&v3_file).is_err());

    // Locate SignalDelivery record in valid_v4:
    // Header: 16 bytes
    // Event 1 (Snapshot): 4 len + 24 header + 48 region + 7 label = 83 bytes -> offset 16 + 4 + 83 = 103
    // Event 2 (SignalDelivery): starts at offset 103
    let sig_rec_offset = 16 + 4 + u32::from_le_bytes(valid_v4[16..20].try_into().unwrap()) as usize;

    // 4. signal_number = 0
    let mut bad_sig0 = valid_v4.clone();
    bad_sig0[sig_rec_offset + 4 + 16..sig_rec_offset + 4 + 20]
        .copy_from_slice(&0_i32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_sig0).is_err());

    // 5. signal_number > 64 (e.g. 65)
    let mut bad_sig65 = valid_v4.clone();
    bad_sig65[sig_rec_offset + 4 + 16..sig_rec_offset + 4 + 20]
        .copy_from_slice(&65_i32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_sig65).is_err());

    // 6. SignalDelivery record shorter than 32-byte header (e.g. 20)
    let mut short_hdr = valid_v4.clone();
    short_hdr[sig_rec_offset..sig_rec_offset + 4].copy_from_slice(&20_u32.to_le_bytes());
    assert!(parse_trace_bytes(&short_hdr).is_err());

    // 7. siginfo_len < 128 (e.g. 64)
    let mut bad_len_short = valid_v4.clone();
    bad_len_short[sig_rec_offset + 4 + 28..sig_rec_offset + 4 + 32]
        .copy_from_slice(&64_u32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_len_short).is_err());

    // 8. siginfo_len > 128 (e.g. 256)
    let mut bad_len_long = valid_v4.clone();
    bad_len_long[sig_rec_offset + 4 + 28..sig_rec_offset + 4 + 32]
        .copy_from_slice(&256_u32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_len_long).is_err());

    // 9. record_length / siginfo_len mismatch
    let mut bad_rec_len = valid_v4.clone();
    bad_rec_len[sig_rec_offset..sig_rec_offset + 4].copy_from_slice(&150_u32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_rec_len).is_err());

    // 10. Truncated raw siginfo bytes
    let truncated_len = valid_v4.len() - 20;
    assert!(parse_trace_bytes(&valid_v4[..truncated_len]).is_err());

    // 11. Raw si_signo mismatch
    let mut bad_raw_signo = valid_v4.clone();
    bad_raw_signo[sig_rec_offset + 4 + 32..sig_rec_offset + 4 + 36]
        .copy_from_slice(&libc::SIGTERM.to_le_bytes());
    assert!(parse_trace_bytes(&bad_raw_signo).is_err());

    // 12. Raw si_errno mismatch
    let mut bad_raw_errno = valid_v4.clone();
    bad_raw_errno[sig_rec_offset + 4 + 36..sig_rec_offset + 4 + 40]
        .copy_from_slice(&99_i32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_raw_errno).is_err());

    // 13. Raw si_code mismatch
    let mut bad_raw_code = valid_v4.clone();
    bad_raw_code[sig_rec_offset + 4 + 40..sig_rec_offset + 4 + 44]
        .copy_from_slice(&99_i32.to_le_bytes());
    assert!(parse_trace_bytes(&bad_raw_code).is_err());

    // 14. Unknown V4 event kind (e.g. kind 8)
    let mut unknown_kind = valid_v4.clone();
    unknown_kind[sig_rec_offset + 4] = 8;
    assert!(parse_trace_bytes(&unknown_kind).is_err());

    // 15. SignalDelivery before required MemoryMapSnapshot in V4
    let raw_sig = create_raw_siginfo(libc::SIGUSR1, 0, libc::SI_USER, 1, 0);
    let mut manual_v4 = Vec::new();
    manual_v4.extend_from_slice(TRACE_HEADER_MAGIC);
    manual_v4.extend_from_slice(&4_u32.to_le_bytes());
    manual_v4.extend_from_slice(&ARCH_X86_64.to_le_bytes());
    manual_v4.push(BYTE_ORDER_LITTLE_ENDIAN);
    manual_v4.push(POINTER_WIDTH_64);
    // SignalDelivery record directly
    manual_v4.extend_from_slice(&160_u32.to_le_bytes());
    manual_v4.push(7); // kind
    manual_v4.extend_from_slice(&[0_u8; 3]);
    manual_v4.extend_from_slice(&1_u64.to_le_bytes()); // event_id = 1
    manual_v4.extend_from_slice(&1_u32.to_le_bytes()); // tid
    manual_v4.extend_from_slice(&libc::SIGUSR1.to_le_bytes());
    manual_v4.extend_from_slice(&0_i32.to_le_bytes());
    manual_v4.extend_from_slice(&libc::SI_USER.to_le_bytes());
    manual_v4.extend_from_slice(&128_u32.to_le_bytes());
    manual_v4.extend_from_slice(&raw_sig);
    // Footer
    manual_v4.extend_from_slice(&1_u64.to_le_bytes());
    manual_v4.extend_from_slice(b"CAUSEND\0");
    assert!(parse_trace_bytes(&manual_v4).is_err());
}

// ---------------------------------------------------------------------------
// 5. Flagship External SIGUSR1 Recording & Replay Proof
// ---------------------------------------------------------------------------

#[test]
fn test_m6_external_sigusr1_recording_and_replay() {
    let fixture = get_fixture_path("signal_external_usr1");
    let trace_path = create_temp_trace_path("usr1_flagship");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_usr1_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let sender_pid = std::process::id() as i32;

    // Spawn thread with bounded watchdog to monitor readiness file and send SIGUSR1
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

    std::env::set_var("CAUSAL_EXPECT_SIGNAL_SENDER_PID", sender_pid.to_string());
    std::env::set_var("CAUSAL_EXPECT_SIGNAL_CODE", libc::SI_USER.to_string());

    let rec_res = run_tracee(
        fixture.to_str().unwrap(),
        &[ready_file.to_str().unwrap().to_string()],
        Some(&trace_path),
    );
    sender_thread.join().unwrap();
    assert_eq!(rec_res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);

    // Verify SignalDelivery event exists in trace
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

    // REPLAY PROOF: Replay with ABSOLUTELY NO external sender thread/signal!
    let replay_ready = std::env::temp_dir().join(format!(
        "causal_replay_ready_usr1_{}.pid",
        std::process::id()
    ));
    let _ = fs::remove_file(&replay_ready);

    let replay_res = run_replay(
        &trace_path,
        fixture.to_str().unwrap(),
        &[replay_ready.to_str().unwrap().to_string()],
    );
    assert_eq!(replay_res, Ok(TraceeTermination::Exited(0)));

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&replay_ready);
}

// ---------------------------------------------------------------------------
// 6. Default-Action SIGTERM Termination Proof
// ---------------------------------------------------------------------------

#[test]
fn test_m6_external_sigterm_default_action_record_and_replay() {
    let fixture = get_fixture_path("signal_external_term");
    let trace_path = create_temp_trace_path("term_default");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_term_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    // Spawn thread with bounded watchdog to send SIGTERM
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

    let rec_res = run_tracee(
        fixture.to_str().unwrap(),
        &[ready_file.to_str().unwrap().to_string()],
        Some(&trace_path),
    );
    sender_thread.join().unwrap();
    assert_eq!(rec_res, Ok(TraceeTermination::Signaled(libc::SIGTERM)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_4);

    let has_sigterm = parsed.events.iter().any(|e| match e {
        TraceEvent::SignalDelivery { signal_number, .. } => *signal_number == libc::SIGTERM,
        _ => false,
    });
    assert!(has_sigterm, "trace must contain SignalDelivery(SIGTERM)");

    // Replay with NO external signal sender
    let replay_ready = std::env::temp_dir().join(format!(
        "causal_replay_ready_term_{}.pid",
        std::process::id()
    ));
    let _ = fs::remove_file(&replay_ready);

    let replay_res = run_replay(
        &trace_path,
        fixture.to_str().unwrap(),
        &[replay_ready.to_str().unwrap().to_string()],
    );
    assert_eq!(replay_res, Ok(TraceeTermination::Signaled(libc::SIGTERM)));

    // Verify CLI exit code is 128 + 15 = 143
    let cli_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_path)
        .arg(&fixture)
        .arg(&replay_ready)
        .output()
        .unwrap();
    assert_eq!(cli_out.status.code(), Some(128 + libc::SIGTERM));

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&replay_ready);
}

// ---------------------------------------------------------------------------
// 7. Multiple Signals & Interleaved Execution
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
// 8. Unsupported Signals & Fault Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_m6_unsupported_stopping_signal_rejected() {
    let fixture = get_fixture_path("signal_stop_unsupported");
    let trace_path = create_temp_trace_path("stop_unsupported");

    let rec_res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert!(rec_res.is_err(), "recording SIGSTOP must fail");
    let err = rec_res.unwrap_err();
    assert!(
        err.contains("unsupported in M6"),
        "expected unsupported diagnostic: {}",
        err
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
// 9. SIGTRAP Classification
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
// 10. Replay Divergence on Unrecorded Live Signal
// ---------------------------------------------------------------------------

#[test]
fn test_m6_replay_divergence_unrecorded_live_signal() {
    let fixture = get_fixture_path("signal_external_usr1");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_diverge_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let region = dummy_stack_region();

    // Construct a synthetic trace without SignalDelivery
    let mut buf = Vec::new();
    let mut writer = TraceWriter::new_v4(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(1, std::slice::from_ref(&region))
        .unwrap();
    writer.write_syscall_enter(1, 39, [0; 6]).unwrap();
    writer.write_syscall_exit(1, 39, 100).unwrap();
    writer.finish().unwrap();

    let trace_path = create_temp_trace_path("unrecorded_diverge");
    fs::write(&trace_path, &buf).unwrap();

    // Spawn thread with bounded watchdog to send unrecorded signal during replay
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

    let res = run_replay(
        &trace_path,
        fixture.to_str().unwrap(),
        &[ready_file.to_str().unwrap().to_string()],
    );
    sender_thread.join().unwrap();

    assert!(res.is_err(), "replay with unrecorded signal must fail");
    let err = res.unwrap_err();
    assert!(
        err.contains("divergence"),
        "expected divergence diagnostic: {}",
        err
    );

    let _ = fs::remove_file(&trace_path);
    let _ = fs::remove_file(&ready_file);
}

// ---------------------------------------------------------------------------
// 11. Historical Maps Query Support
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
// 12. Flagship 100-Replay Stress Test (No External Signal)
// ---------------------------------------------------------------------------

#[test]
fn test_m6_100_replays_stress() {
    let fixture = get_fixture_path("signal_external_usr1");
    let trace_path = create_temp_trace_path("usr1_100_stress");
    let ready_file =
        std::env::temp_dir().join(format!("causal_ready_stress_{}.pid", std::process::id()));
    let _ = fs::remove_file(&ready_file);

    let sender_pid = std::process::id() as i32;

    // Record once with external signal and bounded watchdog
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

    std::env::set_var("CAUSAL_EXPECT_SIGNAL_SENDER_PID", sender_pid.to_string());
    std::env::set_var("CAUSAL_EXPECT_SIGNAL_CODE", libc::SI_USER.to_string());

    let rec_res = run_tracee(
        fixture.to_str().unwrap(),
        &[ready_file.to_str().unwrap().to_string()],
        Some(&trace_path),
    );
    sender_thread.join().unwrap();
    assert_eq!(rec_res, Ok(TraceeTermination::Exited(0)));

    let _ = fs::remove_file(&ready_file);

    // Replay 100 times with ZERO external signals
    for i in 1..=100 {
        let replay_ready = std::env::temp_dir().join(format!(
            "causal_replay_stress_{}_{}.pid",
            std::process::id(),
            i
        ));
        let _ = fs::remove_file(&replay_ready);

        let replay_res = run_replay(
            &trace_path,
            fixture.to_str().unwrap(),
            &[replay_ready.to_str().unwrap().to_string()],
        );
        assert_eq!(
            replay_res,
            Ok(TraceeTermination::Exited(0)),
            "Replay iteration {} failed",
            i
        );

        let _ = fs::remove_file(&replay_ready);
    }

    let _ = fs::remove_file(&trace_path);
}
