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
fn test_deliberate_write_syscall_capture() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/write_hello");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut found_write_entry = false;
    let mut found_write_exit = false;

    let lines: Vec<&str> = stdout.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("syscall-enter") && line.contains("nr=1 ") {
            assert!(
                line.contains("args=[1, "),
                "write entry must have arg0=1 (STDOUT_FILENO): {}",
                line
            );
            assert!(
                line.contains(", 6, "),
                "write entry must have arg2=6 (count): {}",
                line
            );
            found_write_entry = true;

            for exit_line in &lines[i + 1..] {
                if exit_line.starts_with("syscall-exit") && exit_line.contains("nr=1 ") {
                    assert!(
                        exit_line.contains("result=6"),
                        "write exit must report result=6: {}",
                        exit_line
                    );
                    found_write_exit = true;
                    break;
                }
            }
        }
    }

    assert!(
        found_write_entry,
        "did not find intentional SYS_write entry"
    );
    assert!(found_write_exit, "did not find intentional SYS_write exit");
}

#[test]
fn test_getpid_syscall_return_value() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/getpid_test");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut found_getpid = false;
    let lines: Vec<&str> = stdout.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("syscall-enter") && line.contains("nr=39 ") {
            let tid_part = line.split_whitespace().find(|w| w.starts_with("tid="));
            assert!(tid_part.is_some(), "missing tid in entry: {}", line);
            let tid_str = &tid_part.unwrap()[4..];
            let expected_tid: i64 = tid_str.parse().expect("failed to parse tid");

            for exit_line in &lines[i + 1..] {
                if exit_line.starts_with("syscall-exit") && exit_line.contains("nr=39 ") {
                    let expected_result_str = format!("result={}", expected_tid);
                    assert!(
                        exit_line.contains(&expected_result_str),
                        "getpid result must match tid {}: {}",
                        expected_tid,
                        exit_line
                    );
                    found_getpid = true;
                    break;
                }
            }
        }
    }

    assert!(found_getpid, "did not find SYS_getpid entry/exit pair");
}

#[test]
fn test_all_syscall_entries_contain_six_arguments() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/write_hello");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("syscall-enter") {
            let start = line
                .find("args=[")
                .unwrap_or_else(|| panic!("missing args=[ in line: {}", line));
            let end = line[start..]
                .find(']')
                .unwrap_or_else(|| panic!("missing closing ] in line: {}", line));
            let args_slice = &line[start + 6..start + end];
            let args: Vec<&str> = args_slice.split(',').map(|s| s.trim()).collect();
            assert_eq!(
                args.len(),
                6,
                "expected exactly 6 raw arguments in line: {}",
                line
            );
        }
    }
}

#[test]
fn test_sigtrap_not_confused_with_syscall_stop() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/raise_sigtrap");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    assert_eq!(
        output.status.code(),
        Some(133),
        "expected causal to exit with 133 (128+SIGTRAP), got {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("child terminated by signal 5"),
        "stdout should report signal termination: {}",
        stdout
    );
}

#[test]
fn test_syscall_pairing_integrity() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/write_hello");

    let output = Command::new(causal_binary())
        .arg("record")
        .arg(&fixture)
        .output()
        .expect("failed to execute causal");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pending_nr: Option<u64> = None;

    for line in stdout.lines() {
        if line.starts_with("syscall-enter") {
            assert!(
                pending_nr.is_none(),
                "received syscall-enter while previous nr={:?} was still pending: {}",
                pending_nr,
                line
            );
            let nr_part = line
                .split_whitespace()
                .find(|w| w.starts_with("nr="))
                .expect("missing nr= in entry");
            let nr: u64 = nr_part[3..].parse().expect("failed to parse nr");
            pending_nr = Some(nr);
        } else if line.starts_with("syscall-exit") {
            let nr_part = line
                .split_whitespace()
                .find(|w| w.starts_with("nr="))
                .expect("missing nr= in exit");
            let nr: u64 = nr_part[3..].parse().expect("failed to parse nr");
            assert_eq!(
                pending_nr,
                Some(nr),
                "syscall-exit nr={} did not match pending nr={:?}",
                nr,
                pending_nr
            );
            pending_nr = None;
        }
    }
}

#[test]
fn test_m1_100_runs_write_repetition() {
    ensure_fixtures_built();
    let repo_root = get_repo_root();
    let fixture = repo_root.join("tests/bin/write_hello");

    for i in 1..=100 {
        let output = Command::new(causal_binary())
            .arg("record")
            .arg(&fixture)
            .output()
            .unwrap_or_else(|e| panic!("iteration {} failed to execute causal: {}", i, e));

        assert_eq!(
            output.status.code(),
            Some(0),
            "iteration {} failed with unexpected exit status {:?}",
            i,
            output.status.code()
        );
    }
}
