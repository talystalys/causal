use causal::trace::{parse_trace_bytes, TraceEvent, FOOTER_SIZE, HEADER_SIZE};
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
fn test_codec_header_and_empty_trace_round_trip() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.finish().unwrap();

    assert_eq!(buf.len(), HEADER_SIZE + FOOTER_SIZE);
    let events = parse_trace_bytes(&buf).unwrap();
    assert_eq!(events.len(), 0);
}

#[test]
fn test_codec_syscall_enter_round_trip() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();

    let args = [1, 2, 3, 4, 5, 0xffff_ffff_ffff_ffff];
    writer
        .write_syscall_enter(123, 0x1122_3344_5566_7788, args)
        .unwrap();
    writer.finish().unwrap();

    let events = parse_trace_bytes(&buf).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        TraceEvent::SyscallEnter {
            event_id,
            tid,
            number,
            args: decoded_args,
        } => {
            assert_eq!(*event_id, 1);
            assert_eq!(*tid, 123);
            assert_eq!(*number, 0x1122_3344_5566_7788);
            assert_eq!(*decoded_args, args);
        }
        _ => panic!("expected SyscallEnter"),
    }
}

#[test]
fn test_codec_syscall_exit_signed_result_round_trip() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();

    // Write enter first to satisfy pairing validation
    writer.write_syscall_enter(123, 21, [0; 6]).unwrap();
    writer.write_syscall_exit(123, 21, -2).unwrap();
    writer.finish().unwrap();

    let events = parse_trace_bytes(&buf).unwrap();
    assert_eq!(events.len(), 2);
    match &events[1] {
        TraceEvent::SyscallExit {
            event_id,
            tid,
            number,
            result,
        } => {
            assert_eq!(*event_id, 2);
            assert_eq!(*tid, 123);
            assert_eq!(*number, 21);
            assert_eq!(*result, -2);
        }
        _ => panic!("expected SyscallExit"),
    }
}

#[test]
fn test_codec_event_ordering_and_ids() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();

    let id1 = writer.write_syscall_enter(100, 1, [0; 6]).unwrap();
    let id2 = writer.write_syscall_exit(100, 1, 6).unwrap();
    let id3 = writer.write_syscall_enter(100, 231, [0; 6]).unwrap();
    writer.finish().unwrap();

    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(id3, 3);

    let events = parse_trace_bytes(&buf).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_id(), 1);
    assert_eq!(events[1].event_id(), 2);
    assert_eq!(events[2].event_id(), 3);
}

#[test]
fn test_codec_deterministic_serialization_synthetic() {
    let serialize = || -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
        writer
            .write_syscall_enter(42, 1, [1, 0x7fff_1234, 6, 0, 0, 0])
            .unwrap();
        writer.write_syscall_exit(42, 1, 6).unwrap();
        writer
            .write_syscall_enter(42, 231, [0, 0, 0, 0, 0, 0])
            .unwrap();
        writer.finish().unwrap();
        buf
    };

    let run1 = serialize();
    let run2 = serialize();
    assert_eq!(
        run1, run2,
        "synthetic encoding must be byte-for-byte identical"
    );
}

#[test]
fn test_codec_rejection_bad_magic() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.finish().unwrap();

    buf[0..8].copy_from_slice(b"BADMAGIC");
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("invalid trace header magic"), "{}", err);
}

#[test]
fn test_codec_rejection_unsupported_version() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.finish().unwrap();

    buf[8..12].copy_from_slice(&99_u32.to_le_bytes());
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(
        err.contains("unsupported trace format version 99"),
        "{}",
        err
    );
}

#[test]
fn test_codec_rejection_unsupported_architecture() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.finish().unwrap();

    buf[12..14].copy_from_slice(&2_u16.to_le_bytes());
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(
        err.contains("unsupported trace architecture id 2"),
        "{}",
        err
    );
}

#[test]
fn test_codec_rejection_truncated_header() {
    let buf = vec![0_u8; 10];
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("incomplete trace"), "{}", err);
}

#[test]
fn test_codec_rejection_missing_footer() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.write_syscall_enter(10, 1, [0; 6]).unwrap();
    // Do not call finish(), so no footer is written
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("completion footer missing"), "{}", err);
}

#[test]
fn test_codec_rejection_bad_footer_magic() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.finish().unwrap();

    let footer_start = buf.len() - 8;
    buf[footer_start..].copy_from_slice(b"BADFOOT\0");
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("completion footer missing"), "{}", err);
}

#[test]
fn test_codec_rejection_event_count_mismatch() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.write_syscall_enter(10, 231, [0; 6]).unwrap();
    writer.finish().unwrap();

    let count_pos = buf.len() - FOOTER_SIZE;
    buf[count_pos..count_pos + 8].copy_from_slice(&99_u64.to_le_bytes());
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("event count mismatch"), "{}", err);
}

#[test]
fn test_codec_rejection_non_monotonic_event_id() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.write_syscall_enter(10, 1, [0; 6]).unwrap();
    writer.write_syscall_exit(10, 1, 0).unwrap();
    writer.finish().unwrap();

    // Event 2 starts at offset 16 + 76 = 92. Event ID is at offset 92 + 4 + 4 = 100.
    // Overwrite event 2's ID with 1 (duplicate)
    buf[100..108].copy_from_slice(&1_u64.to_le_bytes());
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("non-monotonic event id"), "{}", err);
}

#[test]
fn test_codec_rejection_trailing_garbage() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.finish().unwrap();

    buf.extend_from_slice(b"GARBAGE");
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("completion footer missing"), "{}", err);
}

#[test]
fn test_codec_rejection_malformed_record_length() {
    let mut buf = Vec::new();
    let mut writer = causal::trace::TraceWriter::new(&mut buf).unwrap();
    writer.write_syscall_enter(10, 231, [0; 6]).unwrap();
    writer.finish().unwrap();

    // Overwrite record length at offset 16 with 9999
    buf[16..20].copy_from_slice(&9999_u32.to_le_bytes());
    let err = parse_trace_bytes(&buf).unwrap_err();
    assert!(err.contains("extends past event data region"), "{}", err);
}

#[test]
fn test_cli_record_and_dump_write_hello_round_trip() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/write_hello");
    let trace_file = std::env::temp_dir().join("test_write_hello.causal");
    let _ = fs::remove_file(&trace_file);

    // 1. Record with -o
    let record_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .expect("failed to execute causal record -o");

    assert_eq!(record_out.status.code(), Some(0));
    assert!(trace_file.exists(), "trace file must exist after record -o");

    // 2. Dump
    let dump_out = Command::new(causal_binary())
        .arg("dump")
        .arg(&trace_file)
        .output()
        .expect("failed to execute causal dump");

    assert_eq!(dump_out.status.code(), Some(0));
    let dump_str = String::from_utf8_lossy(&dump_out.stdout);

    // Verify deliberate write in dump
    assert!(
        dump_str.contains("syscall-enter") && dump_str.contains("nr=1 args=[1, "),
        "dump must contain SYS_write entry with fd=1: {}",
        dump_str
    );
    assert!(
        dump_str.contains("syscall-exit") && dump_str.contains("nr=1 result=6"),
        "dump must contain SYS_write exit with result=6: {}",
        dump_str
    );

    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_cli_record_output_long_flag() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/exit_42");
    let trace_file = std::env::temp_dir().join("test_exit_42_long.causal");
    let _ = fs::remove_file(&trace_file);

    let record_out = Command::new(causal_binary())
        .arg("record")
        .arg("--output")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .expect("failed to execute causal record --output");

    assert_eq!(record_out.status.code(), Some(42));
    assert!(
        trace_file.exists(),
        "trace file must exist after record --output"
    );

    let dump_out = Command::new(causal_binary())
        .arg("dump")
        .arg(&trace_file)
        .output()
        .expect("failed to execute causal dump");

    assert_eq!(dump_out.status.code(), Some(0));
    let dump_str = String::from_utf8_lossy(&dump_out.stdout);
    assert!(dump_str.contains("syscall-enter"));

    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_cli_invalid_invocations() {
    // 1. record -o without argument
    let out1 = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out1.stderr).contains("Usage:"));

    // 2. record -o trace without target
    let out2 = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg("trace.causal")
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out2.stderr).contains("Usage:"));

    // 3. dump without trace
    let out3 = Command::new(causal_binary()).arg("dump").output().unwrap();
    assert_eq!(out3.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out3.stderr).contains("Usage:"));

    // 4. dump with extra arguments
    let out4 = Command::new(causal_binary())
        .arg("dump")
        .arg("trace.causal")
        .arg("extra")
        .output()
        .unwrap();
    assert_eq!(out4.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out4.stderr).contains("Usage:"));
}

#[test]
fn test_cli_dump_corrupted_files() {
    let tmp_dir = std::env::temp_dir();

    // 1. Bad magic
    let bad_magic_file = tmp_dir.join("corrupt_bad_magic.causal");
    let mut data = vec![0_u8; 32];
    data[0..8].copy_from_slice(b"NOTMAGIC");
    fs::write(&bad_magic_file, &data).unwrap();

    let out1 = Command::new(causal_binary())
        .arg("dump")
        .arg(&bad_magic_file)
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out1.stderr).contains("invalid trace header magic"));
    let _ = fs::remove_file(&bad_magic_file);

    // 2. Truncated file
    let trunc_file = tmp_dir.join("corrupt_trunc.causal");
    fs::write(&trunc_file, [0_u8; 10]).unwrap();

    let out2 = Command::new(causal_binary())
        .arg("dump")
        .arg(&trunc_file)
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out2.stderr).contains("incomplete trace"));
    let _ = fs::remove_file(&trunc_file);
}

#[test]
fn test_cli_launch_failure_cleans_up_incomplete_trace() {
    let trace_file = std::env::temp_dir().join("launch_fail_cleanup.causal");
    let _ = fs::remove_file(&trace_file);

    let output = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg("./tests/bin/definitely-does-not-exist-54321")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        !trace_file.exists(),
        "incomplete trace file must be removed on launch failure"
    );
}

#[test]
fn test_m2_100_runs_record_dump_stress() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/write_hello");
    let trace_file = std::env::temp_dir().join("m2_stress_test.causal");

    for i in 1..=100 {
        let _ = fs::remove_file(&trace_file);

        let rec_out = Command::new(causal_binary())
            .arg("record")
            .arg("-o")
            .arg(&trace_file)
            .arg(&fixture)
            .output()
            .unwrap_or_else(|e| panic!("iteration {} record failed: {}", i, e));
        assert_eq!(rec_out.status.code(), Some(0));

        let dump_out = Command::new(causal_binary())
            .arg("dump")
            .arg(&trace_file)
            .output()
            .unwrap_or_else(|e| panic!("iteration {} dump failed: {}", i, e));
        assert_eq!(dump_out.status.code(), Some(0));
    }

    let _ = fs::remove_file(&trace_file);
}
