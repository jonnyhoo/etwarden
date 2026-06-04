//! # `process::spawn::tests`
//!
//! **Purpose**: Unit tests for command parsing and spawned child output routing.
//! **Public API**: test module only
//! **Dependencies**: `process::spawn`, `tempfile`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 170 / 220

use std::{fs, path::PathBuf};

use super::*;

#[test]
fn parse_simple_command() {
    let (prog, args) = parse_command("notepad.exe");
    assert_eq!(prog, "notepad.exe");
    assert!(args.is_empty());
}

#[test]
fn parse_command_with_args() {
    let (prog, args) = parse_command("ping -n 1 127.0.0.1");
    assert_eq!(prog, "ping");
    assert_eq!(args, vec!["-n", "1", "127.0.0.1"]);
}

#[test]
fn parse_quoted_program() {
    let (prog, args) = parse_command(r#""C:\Program Files\app.exe" --flag value"#);
    assert_eq!(prog, r"C:\Program Files\app.exe");
    assert_eq!(args, vec!["--flag", "value"]);
}

#[test]
fn parse_quoted_argument() {
    let (prog, args) = parse_command(r#"tool.exe --name "hello world" --flag"#);
    assert_eq!(prog, "tool.exe");
    assert_eq!(args, vec!["--name", "hello world", "--flag"]);
}

#[test]
fn parse_empty_quoted_argument() {
    let (prog, args) = parse_command(r#"tool.exe "" tail"#);
    assert_eq!(prog, "tool.exe");
    assert_eq!(args, vec!["", "tail"]);
}

#[test]
fn parse_quoted_program_no_args() {
    let (prog, args) = parse_command(r#""C:\My App\test.exe""#);
    assert_eq!(prog, r"C:\My App\test.exe");
    assert!(args.is_empty());
}

#[test]
fn parse_unclosed_quote_falls_back() {
    let (prog, args) = parse_command(r#""C:\Program Files\app.exe"#);
    assert_eq!(prog, r#""C:\Program Files\app.exe"#);
    assert!(args.is_empty());
}

#[test]
fn parse_empty_string() {
    let (prog, args) = parse_command("");
    assert!(prog.is_empty());
    assert!(args.is_empty());
}

#[test]
fn parse_whitespace_only() {
    let (prog, args) = parse_command("   ");
    assert!(prog.is_empty());
    assert!(args.is_empty());
}

#[test]
fn spawn_cmd_exits_quickly() {
    let result = spawn_and_get_pid("cmd /C exit 0");
    assert!(result.is_ok(), "spawn should succeed");
    let sr = result.expect("spawn cmd should succeed");
    assert!(sr.pid > 0, "PID should be positive");
    assert_eq!(sr.child.id(), sr.pid);
}

#[test]
fn spawn_routes_stdout_and_stderr_to_files() {
    let temp = tempfile::tempdir().expect("temp dir");
    let stdout_path = temp.path().join("nested/stdout.txt");
    let stderr_path = temp.path().join("nested/stderr.txt");
    let options = SpawnOptions {
        stdout_path: Some(stdout_path.clone()),
        stderr_path: Some(stderr_path.clone()),
    };

    let mut result = spawn_and_get_pid_with_options(
        "cmd /C echo ETWARDEN_STDOUT & echo ETWARDEN_STDERR 1>&2",
        &options,
    )
    .expect("spawn");
    let status = result.child.wait().expect("wait");

    assert!(status.success());
    assert!(fs::read_to_string(stdout_path)
        .expect("stdout file")
        .contains("ETWARDEN_STDOUT"));
    assert!(fs::read_to_string(stderr_path)
        .expect("stderr file")
        .contains("ETWARDEN_STDERR"));
}

#[test]
fn spawn_rejects_empty_output_path() {
    let options = SpawnOptions {
        stdout_path: Some(PathBuf::new()),
        stderr_path: None,
    };

    let result = spawn_and_get_pid_with_options("cmd /C exit 0", &options);

    assert!(
        matches!(result, Err(err) if err.to_string().contains("stdout path must not be empty"))
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
fn spawn_nonexistent_fails() {
    let result = spawn_and_get_pid("nonexistent_program_xyz_12345");
    assert!(result.is_err());
}

#[test]
fn spawn_empty_command_fails_before_process_create() {
    let result = spawn_and_get_pid("   ");
    assert!(
        matches!(result, Err(err) if err.to_string().contains("must not be empty")),
        "empty command should fail"
    );
}
