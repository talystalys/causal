use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn get_repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

static INIT_FIXTURES: std::sync::Once = std::sync::Once::new();

fn ensure_fixtures_built() {
    INIT_FIXTURES.call_once(|| {
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
fn test_normal_termination_exit_42() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/exit_42");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(42),
        "expected causal to exit with 42, got {:?}",
        output.status.code()
    );
    assert!(
        stdout.contains("child exited with status 42"),
        "stdout should report normal exit: {}",
        stdout
    );
}

#[test]
fn test_signal_termination_sigterm() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/signal_term");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // SIGTERM is signal 15; 128 + 15 = 143
    assert_eq!(
        output.status.code(),
        Some(143),
        "expected causal to exit with 143 (128+SIGTERM), got {:?}",
        output.status.code()
    );
    assert!(
        stdout.contains("child terminated by signal 15"),
        "stdout should report signal termination: {}",
        stdout
    );
    assert!(
        !stdout.contains("child exited with status 99"),
        "child must not survive SIGTERM to reach return 99"
    );
}

#[test]
fn test_nonexistent_executable() {
    let output = Command::new(causal_binary())
        .arg("record")
        .arg("./tests/bin/definitely-does-not-exist-12345")
        .output()
        .expect("failed to execute causal");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        output.status.code(),
        Some(0),
        "expected nonzero exit code on launch failure"
    );
    assert!(
        stderr.contains("launch failed: exec failed"),
        "stderr should describe launch/exec failure: {}",
        stderr
    );
    assert!(
        stderr.contains("No such file or directory"),
        "stderr should preserve ENOENT diagnostic: {}",
        stderr
    );
}

#[test]
fn test_permission_denied_executable() {
    let temp_dir = tempfile_dir();
    let non_exec_file = temp_dir.join("non_exec_binary");
    fs::write(&non_exec_file, b"#!/bin/sh\necho hello\n").expect("failed to write temp file");
    fs::set_permissions(&non_exec_file, fs::Permissions::from_mode(0o644))
        .expect("failed to set non-executable permissions");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&non_exec_file)
        .output()
        .expect("failed to execute causal");

    let _ = fs::remove_file(&non_exec_file);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        output.status.code(),
        Some(0),
        "expected nonzero exit code on launch failure"
    );
    assert!(
        stderr.contains("launch failed: exec failed"),
        "stderr should describe launch/exec failure: {}",
        stderr
    );
    assert!(
        stderr.contains("Permission denied"),
        "stderr should preserve EACCES diagnostic: {}",
        stderr
    );
}

#[test]
fn test_invalid_cli_invocations() {
    // 1. No arguments
    let out1 = Command::new(causal_binary())
        .output()
        .expect("failed to execute causal");
    assert_eq!(out1.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out1.stderr).contains("Usage:"));

    // 2. Only 'record' without target
    let out2 = Command::new(causal_binary())
        .arg("record")
        .output()
        .expect("failed to execute causal");
    assert_eq!(out2.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out2.stderr).contains("Usage:"));

    // 3. Unknown subcommand
    let out3 = Command::new(causal_binary())
        .arg("nonsense")
        .arg("./tests/bin/exit_42")
        .output()
        .expect("failed to execute causal");
    assert_eq!(out3.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out3.stderr).contains("Usage:"));
}

#[test]
fn test_target_with_arguments() {
    let output = Command::new(causal_binary())
        .arg("record")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 42")
        .output()
        .expect("failed to execute causal");

    assert_eq!(output.status.code(), Some(42));
    assert!(String::from_utf8_lossy(&output.stdout).contains("child exited with status 42"));
}

#[test]
fn test_lifecycle_100_runs_repetition() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/exit_42");

    for i in 1..=100 {
        let output = Command::new(causal_binary())
            .arg("record")
            .arg(&fixture)
            .output()
            .unwrap_or_else(|e| panic!("iteration {} failed to execute causal: {}", i, e));

        assert_eq!(
            output.status.code(),
            Some(42),
            "iteration {} failed with unexpected exit status {:?}",
            i,
            output.status.code()
        );
    }
}

fn tempfile_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push("causal_test");
    let _ = fs::create_dir_all(&dir);
    dir
}
