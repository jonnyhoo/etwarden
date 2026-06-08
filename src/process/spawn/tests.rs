//! # `process::spawn::tests`
//!
//! **Purpose**: Unit tests for spawned child process creation and output routing.
//! **Public API**: test module only
//! **Dependencies**: `process::spawn`, `tempfile`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 200

use std::{fs, path::PathBuf};

use super::*;

/// Resume the suspended primary thread, then wait for process exit.
fn resume_and_wait(result: &SpawnResult) {
    unsafe {
        use windows::Win32::System::Threading::{ResumeThread, WaitForSingleObject};
        ResumeThread(result.thread_handle());
        let _ = WaitForSingleObject(result.process_handle(), 0xFFFF_FFFF);
    }
}

#[test]
fn spawn_cmd_exits_quickly() {
    let result = spawn_and_get_pid("cmd /C exit 0");
    assert!(result.is_ok(), "spawn should succeed: {:?}", result.err());
    let result = result.expect("spawn succeeded");
    assert!(result.pid > 0, "PID should be positive");

    resume_and_wait(&result);

    let mut exit_code = 0u32;
    unsafe {
        let _ = windows::Win32::System::Threading::GetExitCodeProcess(
            result.process_handle(),
            &raw mut exit_code,
        );
    }
    assert_eq!(exit_code, 0, "exit code should be 0");
}

#[test]
fn spawn_nonexistent_exits_nonzero() {
    // cmd.exe /C wraps the command, so CreateProcessW always succeeds.
    // The child process exits with non-zero code for an invalid command.
    let result = spawn_and_get_pid("nonexistent_program_xyz_12345");
    assert!(
        result.is_ok(),
        "spawn should succeed (cmd.exe wraps): {:?}",
        result.err()
    );
    let result = result.expect("spawn succeeded");
    assert!(result.pid > 0, "PID should be positive");
    resume_and_wait(&result);

    let mut exit_code = 0u32;
    unsafe {
        let _ = windows::Win32::System::Threading::GetExitCodeProcess(
            result.process_handle(),
            &raw mut exit_code,
        );
    }
    assert_ne!(
        exit_code, 0,
        "exit code should be non-zero for nonexistent program"
    );
}

#[test]
fn spawn_rejects_shared_stdout_and_stderr_path() {
    let path = PathBuf::from("same.log");
    let options = SpawnOptions {
        stdout_path: Some(path.clone()),
        stderr_path: Some(path),
    };

    let result = spawn_and_get_pid_with_options("cmd /C exit 0", &options);

    assert!(matches!(result, Err(err) if err.to_string().contains("paths must differ")));
}

#[test]
fn spawn_writes_stdout_to_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stdout_path = dir.path().join("out.log");
    let options = SpawnOptions {
        stdout_path: Some(stdout_path.clone()),
        stderr_path: None,
    };

    let result = spawn_and_get_pid_with_options("cmd /C echo hello", &options);
    assert!(result.is_ok(), "spawn should succeed: {:?}", result.err());

    let result = result.expect("spawn succeeded");
    resume_and_wait(&result);

    let content = fs::read_to_string(&stdout_path).expect("read stdout file");
    assert!(
        content.contains("hello"),
        "stdout file should contain 'hello', got: {content}"
    );
}

#[test]
fn spawn_writes_stderr_to_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stderr_path = dir.path().join("err.log");
    let options = SpawnOptions {
        stdout_path: None,
        stderr_path: Some(stderr_path.clone()),
    };

    let result = spawn_and_get_pid_with_options("cmd /C echo error 1>&2", &options);
    assert!(result.is_ok(), "spawn should succeed: {:?}", result.err());

    let result = result.expect("spawn succeeded");
    resume_and_wait(&result);

    let content = fs::read_to_string(&stderr_path).expect("read stderr file");
    assert!(
        content.contains("error"),
        "stderr file should contain 'error', got: {content}"
    );
}
