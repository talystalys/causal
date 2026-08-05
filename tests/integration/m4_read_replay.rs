use causal::replay::write_process_memory_exact;
use causal::trace::{
    parse_trace_bytes, read_trace_file_versioned, TraceEvent, TraceWriter, SYS_GETPID_X86_64,
    SYS_READ_X86_64, TRACE_VERSION_1, TRACE_VERSION_2,
};
use causal::tracer::{kill_and_reap, launch_traced_child, read_process_memory_exact};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ensure_fixtures_built() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let repo_root = get_repo_root();
        let script = repo_root.join("scripts/build-fixtures.sh");
        let status = Command::new(&script)
            .current_dir(&repo_root)
            .status()
            .expect("failed to execute build-fixtures.sh");
        assert!(status.success(), "fixture build script failed");
    });
}

fn causal_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_causal"))
}

#[test]
fn test_m4_deleted_source_and_short_read_replay() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_replay");
    let tmp_dir = std::env::temp_dir();
    let test_input = tmp_dir.join("m4_test_input_deleted.txt");
    let trace_file = tmp_dir.join("m4_test_trace_deleted.causal");

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);

    // 1. Create source file containing expected payload
    fs::write(&test_input, b"CAUSAL_M4_PAYLOAD_21B").unwrap();

    // 2. Record fixture execution
    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("record failed");
    assert_eq!(rec_out.status.code(), Some(0));

    // 3. Inspect trace: verify V2, SYS_read result=21, and KernelMemoryWrite payload
    let parsed = read_trace_file_versioned(&trace_file).expect("trace parse failed");
    assert_eq!(parsed.version, TRACE_VERSION_2);

    let mut found_read_exit = false;
    let mut found_mem_write = false;

    for (i, event) in parsed.events.iter().enumerate() {
        if let TraceEvent::SyscallExit { number, result, .. } = event {
            if *number == SYS_READ_X86_64 && *result == 21 {
                found_read_exit = true;
                if let Some(TraceEvent::KernelMemoryWrite { data, .. }) = parsed.events.get(i + 1) {
                    found_mem_write = true;
                    assert_eq!(data, b"CAUSAL_M4_PAYLOAD_21B");
                }
            }
        }
    }
    assert!(
        found_read_exit,
        "trace must contain read exit with result 21"
    );
    assert!(
        found_mem_write,
        "trace must contain KernelMemoryWrite with recorded bytes"
    );

    // 4. Delete the source file
    fs::remove_file(&test_input).unwrap();

    // 5. Run fixture natively (negative control): O_CREAT makes an empty file, read returns 0, fixture exits 42
    let native_out = Command::new(&fixture)
        .arg(&test_input)
        .output()
        .expect("native run failed");
    assert_eq!(
        native_out.status.code(),
        Some(42),
        "native fixture must exit 42 when source file was deleted"
    );

    // 6. Replay under CAUSAL: live read is suppressed, recorded bytes are injected, exits 0
    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("replay failed");

    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "replay must succeed with exit 0. Stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("replay-memory"),
        "stderr must contain replay-memory diagnostic: {}",
        stderr
    );
    assert!(
        stderr.contains("suppressed=-38"),
        "diagnostic must contain -ENOSYS suppression sentinel: {}",
        stderr
    );
    assert!(
        stderr.contains("len=21"),
        "diagnostic must contain payload length: {}",
        stderr
    );

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m4_modified_source_replay() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_replay");
    let tmp_dir = std::env::temp_dir();
    let test_input = tmp_dir.join("m4_test_input_modified.txt");
    let trace_file = tmp_dir.join("m4_test_trace_modified.causal");

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);

    fs::write(&test_input, b"CAUSAL_M4_PAYLOAD_21B").unwrap();

    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("record failed");
    assert_eq!(rec_out.status.code(), Some(0));

    // Overwrite input file with completely different content
    fs::write(&test_input, b"CORRUPTED_WRONG_DATA_BYTES_HERE").unwrap();

    // Native run fails (reads wrong bytes)
    let native_out = Command::new(&fixture).arg(&test_input).output().unwrap();
    assert_eq!(native_out.status.code(), Some(42));

    // Replay succeeds (suppresses live read, injects original recorded bytes)
    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .unwrap();

    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "replay must succeed even when source is modified"
    );

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m4_mixed_getpid_and_read_replay() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/mixed_replay");
    let tmp_dir = std::env::temp_dir();
    let test_input = tmp_dir.join("m4_test_input_mixed.txt");
    let trace_file = tmp_dir.join("m4_test_trace_mixed.causal");

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);

    fs::write(&test_input, b"CAUSAL_M4_PAYLOAD_21B").unwrap();

    // 1. Record without CAUSAL_EXPECT_GETPID
    let rec_out = Command::new(causal_binary())
        .env_remove("CAUSAL_EXPECT_GETPID")
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("record failed");
    assert_eq!(rec_out.status.code(), Some(0));

    let parsed = read_trace_file_versioned(&trace_file).expect("trace parse failed");
    let mut recorded_pid = 0;
    let mut recorded_read_len = 0;

    for event in &parsed.events {
        if let TraceEvent::SyscallExit { number, result, .. } = event {
            if *number == SYS_GETPID_X86_64 {
                recorded_pid = *result;
            } else if *number == SYS_READ_X86_64 && *result > 0 {
                recorded_read_len = *result;
            }
        }
    }
    assert!(recorded_pid > 0, "must find SYS_getpid exit in trace");
    assert_eq!(
        recorded_read_len, 21,
        "must find SYS_read result 21 in trace"
    );

    // 2. Delete source file
    fs::remove_file(&test_input).unwrap();

    // 3. Native run fails with exit 42
    let native_out = Command::new(&fixture)
        .env("CAUSAL_EXPECT_GETPID", recorded_pid.to_string())
        .arg(&test_input)
        .output()
        .unwrap();
    assert_eq!(native_out.status.code(), Some(42));

    // 4. Replay under CAUSAL: both getpid AND read are substituted in one stream
    let replay_out = Command::new(causal_binary())
        .env("CAUSAL_EXPECT_GETPID", recorded_pid.to_string())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "mixed replay must succeed with exit 0. Stderr: {}",
        stderr
    );

    // Verify both diagnostics are emitted
    assert!(
        stderr.contains("replay-substitute") && stderr.contains("syscall=getpid"),
        "stderr must contain getpid substitution diagnostic: {}",
        stderr
    );
    assert!(
        stderr.contains("replay-memory") && stderr.contains("syscall=read"),
        "stderr must contain read memory substitution diagnostic: {}",
        stderr
    );

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m4_remote_memory_transfer_failure_exactness() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/exit_42");

    // Launch a controlled tracee under ptrace
    let pid = launch_traced_child(fixture.to_str().unwrap(), &[]).unwrap();

    // Wait for bootstrap stop
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // 1. Test read_process_memory_exact with invalid address 0x0 -> must return Err
    let read_err = read_process_memory_exact(pid, 0x0, 64).unwrap_err();
    assert!(
        read_err.contains("process_vm_readv failed"),
        "must return descriptive OS error for invalid read address: {}",
        read_err
    );

    // 2. Test write_process_memory_exact with invalid address 0x0 -> must return Err
    let write_err = write_process_memory_exact(pid, 0x0, b"test_payload").unwrap_err();
    assert!(
        write_err.contains("process_vm_writev failed"),
        "must return descriptive OS error for invalid write address: {}",
        write_err
    );

    // Clean up child process
    kill_and_reap(pid);
}

#[test]
fn test_m4_eof_replay() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_eof");
    let tmp_dir = std::env::temp_dir();
    let test_input = tmp_dir.join("m4_test_input_eof.txt");
    let trace_file = tmp_dir.join("m4_test_trace_eof.causal");

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);

    // Create empty file
    fs::write(&test_input, b"").unwrap();

    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("record failed");
    assert_eq!(rec_out.status.code(), Some(0));

    // Trace must have read exit=0 and NO memory write event attached
    let parsed = read_trace_file_versioned(&trace_file).unwrap();
    let mut found_eof_exit = false;
    for event in &parsed.events {
        if let TraceEvent::SyscallExit { number, result, .. } = event {
            if *number == SYS_READ_X86_64 && *result == 0 {
                found_eof_exit = true;
            }
        }
    }
    assert!(found_eof_exit);

    // Modify file to contain data
    fs::write(&test_input, b"NOW_CONTAINS_DATA").unwrap();

    // Native run fails (reads data, not EOF)
    let native_out = Command::new(&fixture).arg(&test_input).output().unwrap();
    assert_eq!(native_out.status.code(), Some(42));

    // Replay succeeds (suppresses live read, injects 0, buffer untouched)
    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .unwrap();

    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "replay must reproduce EOF behavior"
    );

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m4_zero_byte_count_replay() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_zero_count");
    let tmp_dir = std::env::temp_dir();
    let test_input = tmp_dir.join("m4_test_input_zero_count.txt");
    let trace_file = tmp_dir.join("m4_test_trace_zero_count.causal");

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);

    fs::write(&test_input, b"SOME_DATA_TO_READ").unwrap();

    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("record failed");
    assert_eq!(rec_out.status.code(), Some(0));

    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .unwrap();

    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "replay must succeed for zero-count read"
    );

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m4_failed_read_replay() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_failed");
    let tmp_dir = std::env::temp_dir();
    let trace_file = tmp_dir.join("m4_test_trace_failed.causal");

    let _ = fs::remove_file(&trace_file);

    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .expect("record failed");
    assert_eq!(rec_out.status.code(), Some(0));

    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .unwrap();

    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "replay must reproduce negative error return for failed read"
    );

    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m4_v1_compatibility_and_rejection() {
    // 1. Synthetic V1 trace with SYS_getpid can still be parsed
    let mut v1_buf = Vec::new();
    let mut writer = TraceWriter::new_v1(&mut v1_buf).unwrap();
    assert_eq!(writer.version(), TRACE_VERSION_1);
    writer.write_syscall_enter(100, 39, [0; 6]).unwrap();
    writer.write_syscall_exit(100, 39, 1234).unwrap();
    writer.finish().unwrap();

    let parsed = parse_trace_bytes(&v1_buf).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_1);
    assert_eq!(parsed.events.len(), 2);

    // 2. V1 trace with positive SYS_read cannot be memory-replayed
    let mut v1_read_buf = Vec::new();
    let mut writer2 = TraceWriter::new_v1(&mut v1_read_buf).unwrap();
    writer2
        .write_syscall_enter(100, 0, [4, 0x7ffd_1234, 64, 0, 0, 0])
        .unwrap();
    writer2.write_syscall_exit(100, 0, 18).unwrap();
    writer2.finish().unwrap();

    let tmp_v1 = std::env::temp_dir().join("test_v1_read.causal");
    fs::write(&tmp_v1, &v1_read_buf).unwrap();

    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_replay");
    let dummy_path = std::env::temp_dir().join("dummy_m4.txt");
    fs::write(&dummy_path, b"dummy").unwrap();

    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&tmp_v1)
        .arg(&fixture)
        .arg(&dummy_path)
        .output()
        .unwrap();

    assert_eq!(replay_out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert!(
        stderr.contains("V1 trace cannot replay SYS_read memory output"),
        "must explicitly reject V1 read memory replay: {}",
        stderr
    );

    let _ = fs::remove_file(&tmp_v1);
    let _ = fs::remove_file(&dummy_path);
}

#[test]
fn test_m4_deterministic_v2_serialization() {
    let serialize = || -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v2(&mut buf).unwrap();
        let enter_id = writer
            .write_syscall_enter(42, 0, [4, 0x7fff_1000, 64, 0, 0, 0])
            .unwrap();
        let exit_id = writer.write_syscall_exit(42, 0, 5).unwrap();
        writer
            .write_kernel_memory_write(42, exit_id, 0x7fff_1000, b"hello")
            .unwrap();
        assert_eq!(enter_id, 1);
        assert_eq!(exit_id, 2);
        writer.finish().unwrap();
        buf
    };

    let run1 = serialize();
    let run2 = serialize();
    assert_eq!(
        run1, run2,
        "synthetic V2 trace encoding must be byte-for-byte identical"
    );
}

#[test]
fn test_m4_v2_corruption_cases() {
    // 1. KernelMemoryWrite in V1 file -> rejected
    let mut v1_buf = Vec::new();
    let mut w = TraceWriter::new_v1(&mut v1_buf).unwrap();
    w.write_syscall_enter(1, 0, [0; 6]).unwrap();
    w.write_syscall_exit(1, 0, 5).unwrap();
    w.finish().unwrap();
    let mut forged_v1 = v1_buf.clone();
    forged_v1[20] = 3; // kind=3
    assert!(parse_trace_bytes(&forged_v1).is_err());

    // 2. Unknown V2 event kind -> rejected
    let mut v2_unknown = Vec::new();
    let mut w = TraceWriter::new_v2(&mut v2_unknown).unwrap();
    w.write_syscall_enter(1, 39, [0; 6]).unwrap();
    w.write_syscall_exit(1, 39, 10).unwrap();
    w.finish().unwrap();
    v2_unknown[20] = 99; // unknown kind
    let err = parse_trace_bytes(&v2_unknown).unwrap_err();
    assert!(err.contains("unknown event kind 99"), "{}", err);

    // 3. Positive SYS_read missing required KernelMemoryWrite in V2 -> rejected
    let mut missing_mem = Vec::new();
    let mut w = TraceWriter::new_v2(&mut missing_mem).unwrap();
    w.write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    w.write_syscall_exit(1, 0, 18).unwrap();
    w.finish().unwrap();
    let err = parse_trace_bytes(&missing_mem).unwrap_err();
    assert!(
        err.contains("missing required KernelMemoryWrite event"),
        "{}",
        err
    );

    // 4. KernelMemoryWrite with mismatched source_event_id -> rejected
    let mut wrong_source = Vec::new();
    let mut w = TraceWriter::new_v2(&mut wrong_source).unwrap();
    w.write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    let exit_id = w.write_syscall_exit(1, 0, 4).unwrap();
    w.write_kernel_memory_write(1, exit_id + 99, 0x7ffd_1000, b"test")
        .unwrap();
    w.finish().unwrap();
    let err = parse_trace_bytes(&wrong_source).unwrap_err();
    assert!(
        err.contains("does not match immediately preceding exit event"),
        "{}",
        err
    );

    // 5. C1: KernelMemoryWrite source_event_id references a SyscallEnter (not a SyscallExit) -> rejected
    let mut source_is_enter = Vec::new();
    let mut w = TraceWriter::new_v2(&mut source_is_enter).unwrap();
    let enter_id = w
        .write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    w.write_kernel_memory_write(1, enter_id, 0x7ffd_1000, b"test")
        .unwrap();
    w.finish().unwrap();
    let err = parse_trace_bytes(&source_is_enter).unwrap_err();
    assert!(
        err.contains("points to a SyscallEnter, expected SyscallExit"),
        "{}",
        err
    );

    // 6. C2: KernelMemoryWrite attached to SyscallExit whose syscall is NOT SYS_read -> rejected
    let mut source_not_read = Vec::new();
    let mut w = TraceWriter::new_v2(&mut source_not_read).unwrap();
    w.write_syscall_enter(1, 1, [1, 0x7ffd_1000, 4, 0, 0, 0])
        .unwrap();
    let write_exit_id = w.write_syscall_exit(1, 1, 4).unwrap();
    w.write_kernel_memory_write(1, write_exit_id, 0x7ffd_1000, b"test")
        .unwrap();
    w.finish().unwrap();
    let err = parse_trace_bytes(&source_not_read).unwrap_err();
    assert!(
        err.contains("attached to SyscallExit nr=1, expected SYS_read (0)"),
        "{}",
        err
    );

    // 7. C3 / Z: KernelMemoryWrite attached to SYS_read whose result is 0 -> rejected
    let mut mem_after_zero_read = Vec::new();
    let mut w = TraceWriter::new_v2(&mut mem_after_zero_read).unwrap();
    w.write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    let zero_exit_id = w.write_syscall_exit(1, 0, 0).unwrap();
    w.write_kernel_memory_write(1, zero_exit_id, 0x7ffd_1000, b"")
        .unwrap();
    w.finish().unwrap();
    let err = parse_trace_bytes(&mem_after_zero_read).unwrap_err();
    assert!(
        err.contains("attached to zero-result read exit event"),
        "{}",
        err
    );

    // 8. C4 / Z: KernelMemoryWrite attached to SYS_read whose result is negative -> rejected
    let mut mem_after_failed_read = Vec::new();
    let mut w = TraceWriter::new_v2(&mut mem_after_failed_read).unwrap();
    w.write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    let fail_exit_id = w.write_syscall_exit(1, 0, -9).unwrap();
    w.write_kernel_memory_write(1, fail_exit_id, 0x7ffd_1000, b"")
        .unwrap();
    w.finish().unwrap();
    let err = parse_trace_bytes(&mem_after_failed_read).unwrap_err();
    assert!(
        err.contains("attached to failed read exit event"),
        "{}",
        err
    );

    // 9. KernelMemoryWrite data length != read result -> rejected
    let mut mismatched_len = Vec::new();
    let mut w = TraceWriter::new_v2(&mut mismatched_len).unwrap();
    w.write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    let exit_id = w.write_syscall_exit(1, 0, 10).unwrap();
    w.write_kernel_memory_write(1, exit_id, 0x7ffd_1000, b"short")
        .unwrap(); // len 5 != 10
    w.finish().unwrap();
    let err = parse_trace_bytes(&mismatched_len).unwrap_err();
    assert!(err.contains("does not match read result"), "{}", err);

    // 10. KernelMemoryWrite recorded address != enter buffer address -> rejected
    let mut wrong_addr = Vec::new();
    let mut w = TraceWriter::new_v2(&mut wrong_addr).unwrap();
    w.write_syscall_enter(1, 0, [4, 0x7ffd_1000, 64, 0, 0, 0])
        .unwrap();
    let exit_id = w.write_syscall_exit(1, 0, 4).unwrap();
    w.write_kernel_memory_write(1, exit_id, 0x7ffd_9999, b"test")
        .unwrap(); // addr differs
    w.finish().unwrap();
    let err = parse_trace_bytes(&wrong_addr).unwrap_err();
    assert!(
        err.contains("does not match read entry buffer address"),
        "{}",
        err
    );
}

#[test]
fn test_m4_100_replays_stress() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/read_replay");
    let tmp_dir = std::env::temp_dir();
    let test_input = tmp_dir.join("m4_stress_input.txt");
    let trace_file = tmp_dir.join("m4_stress_trace.causal");

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);

    // Record ONCE with expected content
    fs::write(&test_input, b"CAUSAL_M4_PAYLOAD_21B").unwrap();
    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .arg(&test_input)
        .output()
        .expect("record failed for stress");
    assert_eq!(rec_out.status.code(), Some(0));

    // Overwrite the input file with DIFFERENT corrupt bytes to ensure external independence
    fs::write(&test_input, b"WRONG_DATA_EVERY_SINGLE_REPLAY_ITERATION").unwrap();

    // Replay 100 times against the single recorded trace
    for i in 1..=100 {
        let replay_out = Command::new(causal_binary())
            .arg("replay")
            .arg(&trace_file)
            .arg(&fixture)
            .arg(&test_input)
            .output()
            .unwrap_or_else(|e| panic!("iteration {} replay failed: {}", i, e));

        assert_eq!(
            replay_out.status.code(),
            Some(0),
            "iteration {} failed: stderr={}",
            i,
            String::from_utf8_lossy(&replay_out.stderr)
        );
    }

    let _ = fs::remove_file(&test_input);
    let _ = fs::remove_file(&trace_file);
}
