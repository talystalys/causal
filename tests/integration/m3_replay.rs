use causal::replay::SYS_GETPID_X86_64;
use causal::trace::{read_trace_file, TraceEvent};
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
fn test_m3_record_negative_control_and_replay_substitution() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/getpid_replay");
    let trace_file = std::env::temp_dir().join("test_m3_getpid_replay.causal");
    let _ = fs::remove_file(&trace_file);

    // 1. Test A: Record source trace
    let rec_out = Command::new(causal_binary())
        .env_remove("CAUSAL_EXPECT_GETPID")
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .expect("failed to execute causal record -o");

    assert_eq!(rec_out.status.code(), Some(0));
    assert!(trace_file.exists());

    let events = read_trace_file(&trace_file).expect("trace must parse cleanly");
    assert!(!events.is_empty());

    let mut recorded_getpid_res: Option<i64> = None;
    for event in &events {
        if let TraceEvent::SyscallExit { number, result, .. } = event {
            if *number == SYS_GETPID_X86_64 {
                recorded_getpid_res = Some(*result);
                break;
            }
        }
    }

    let recorded_pid = recorded_getpid_res.expect("trace must contain SYS_getpid exit");
    assert!(recorded_pid > 0);

    // 2. Test B: Native negative control
    // Running the fixture natively with CAUSAL_EXPECT_GETPID=recorded_pid should fail with exit 42
    // (unless coincidental PID reuse occurs, in which case we retry).
    let mut native_exit = 0;
    for _ in 0..5 {
        let native_out = Command::new(&fixture)
            .env("CAUSAL_EXPECT_GETPID", recorded_pid.to_string())
            .output()
            .expect("failed to execute fixture natively");
        native_exit = native_out.status.code().unwrap_or(-1);
        if native_exit == 42 {
            break;
        }
    }
    assert_eq!(
        native_exit, 42,
        "native negative control must exit 42 when live PID != recorded PID"
    );

    // 3. Test C, D, E: Replay substitution under CAUSAL
    let replay_out = Command::new(causal_binary())
        .env("CAUSAL_EXPECT_GETPID", recorded_pid.to_string())
        .arg("replay")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .expect("failed to execute causal replay");

    assert_eq!(
        replay_out.status.code(),
        Some(0),
        "replay must exit 0 when getpid is substituted with recorded value. Stderr: {}",
        String::from_utf8_lossy(&replay_out.stderr)
    );

    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert!(
        stderr.contains("replay-substitute"),
        "stderr must contain substitution diagnostic: {}",
        stderr
    );
    assert!(
        stderr.contains(&format!("recorded={}", recorded_pid)),
        "diagnostic must contain recorded PID: {}",
        stderr
    );
    assert!(
        stderr.contains("suppressed=-38"),
        "diagnostic must show -ENOSYS (-38) suppression sentinel: {}",
        stderr
    );
    assert!(
        stderr.contains(&format!("injected={}", recorded_pid)),
        "diagnostic must show injected PID: {}",
        stderr
    );

    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m3_wrong_target_divergence() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let getpid_fixture = repo_root.join("tests/bin/getpid_replay");
    let write_fixture = repo_root.join("tests/bin/write_hello");
    let trace_file = std::env::temp_dir().join("test_m3_divergence.causal");
    let _ = fs::remove_file(&trace_file);

    // Record getpid_replay
    let rec_out = Command::new(causal_binary())
        .env_remove("CAUSAL_EXPECT_GETPID")
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&getpid_fixture)
        .output()
        .expect("failed to record");
    assert_eq!(rec_out.status.code(), Some(0));

    // Attempt replay against write_hello
    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&write_fixture)
        .output()
        .expect("failed to execute replay");

    assert_ne!(
        replay_out.status.code(),
        Some(0),
        "replay against incompatible target must exit nonzero"
    );

    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert!(
        stderr.contains("replay divergence"),
        "stderr must report replay divergence: {}",
        stderr
    );

    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m3_corrupt_trace_rejected_before_launch() {
    let tmp_dir = std::env::temp_dir();
    let corrupt_trace = tmp_dir.join("test_m3_corrupt_prelaunch.causal");
    fs::write(&corrupt_trace, b"NOTMAGIC123456789012345678901234").unwrap();

    // Pass a nonexistent target to prove parse-before-launch (error must be trace error, not exec error)
    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&corrupt_trace)
        .arg("./definitely_does_not_exist_target_45678")
        .output()
        .unwrap();

    assert_eq!(replay_out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert!(
        stderr.contains("invalid trace header magic"),
        "error must be trace validation failure: {}",
        stderr
    );

    let _ = fs::remove_file(&corrupt_trace);
}

#[test]
fn test_m3_trace_without_getpid_rejected() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let write_fixture = repo_root.join("tests/bin/write_hello");
    let trace_file = std::env::temp_dir().join("test_m3_no_getpid.causal");
    let _ = fs::remove_file(&trace_file);

    // Record write_hello (which contains no getpid syscall)
    let rec_out = Command::new(causal_binary())
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&write_fixture)
        .output()
        .unwrap();
    assert_eq!(rec_out.status.code(), Some(0));

    // Replay write_hello trace against write_hello
    let replay_out = Command::new(causal_binary())
        .arg("replay")
        .arg(&trace_file)
        .arg(&write_fixture)
        .output()
        .unwrap();

    assert_eq!(replay_out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&replay_out.stderr);
    assert!(
        stderr.contains("no supported SYS_getpid substitution"),
        "must reject trace without getpid: {}",
        stderr
    );

    let _ = fs::remove_file(&trace_file);
}

#[test]
fn test_m3_invalid_cli_invocations() {
    // 1. replay without args
    let out1 = Command::new(causal_binary())
        .arg("replay")
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out1.stderr).contains("Usage:"));

    // 2. replay with only trace arg
    let out2 = Command::new(causal_binary())
        .arg("replay")
        .arg("trace.causal")
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out2.stderr).contains("Usage:"));
}

#[test]
fn test_m3_100_replays_stress() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/getpid_replay");
    let trace_file = std::env::temp_dir().join("test_m3_100_stress.causal");
    let _ = fs::remove_file(&trace_file);

    // Record ONCE
    let rec_out = Command::new(causal_binary())
        .env_remove("CAUSAL_EXPECT_GETPID")
        .arg("record")
        .arg("-o")
        .arg(&trace_file)
        .arg(&fixture)
        .output()
        .expect("failed to record for stress test");
    assert_eq!(rec_out.status.code(), Some(0));

    let events = read_trace_file(&trace_file).expect("trace must parse");
    let mut recorded_pid = 0;
    for event in &events {
        if let TraceEvent::SyscallExit { number, result, .. } = event {
            if *number == SYS_GETPID_X86_64 {
                recorded_pid = *result;
                break;
            }
        }
    }
    assert!(recorded_pid > 0);

    // Replay 100 times against the single recorded trace
    for i in 1..=100 {
        let replay_out = Command::new(causal_binary())
            .env("CAUSAL_EXPECT_GETPID", recorded_pid.to_string())
            .arg("replay")
            .arg(&trace_file)
            .arg(&fixture)
            .output()
            .unwrap_or_else(|e| panic!("iteration {} replay failed: {}", i, e));

        assert_eq!(
            replay_out.status.code(),
            Some(0),
            "iteration {} replay failed: stderr={}",
            i,
            String::from_utf8_lossy(&replay_out.stderr)
        );
    }

    let _ = fs::remove_file(&trace_file);
}
