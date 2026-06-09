//! # `process_schema_compat`
//!
//! **Purpose**: Snapshot tests for process-command `OutputLine` variants.
//! **Public API**: integration test only
//! **Dependencies**: `etwarden`, `insta`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 120

use std::collections::HashSet;

use etwarden::{
    output::schema::{
        process_entry_to_line, process_kill_result_to_line, spawn_target_to_line, OutputLine,
    },
    process::{KillProcessResult, ProcessEntry},
};

fn process_entry() -> ProcessEntry {
    ProcessEntry {
        pid: 4242,
        parent_pid: Some(1000),
        name: "claude.exe".into(),
        exe: Some(r"C:\Users\agent\AppData\Local\Programs\Claude\claude.exe".into()),
        command_line: Some(r"claude.exe --debug".into()),
        session_id: Some(1),
        current_session: true,
        started_at_unix_secs: 1_781_013_600,
    }
}

#[test]
fn snapshot_process_line() {
    let line = process_entry_to_line(process_entry());

    insta::assert_json_snapshot!("process_line", line);
}

#[test]
fn snapshot_process_kill_line() {
    let result = KillProcessResult {
        pid: 4242,
        process: Some(process_entry()),
        success: true,
        action: "terminate_process".into(),
        error: None,
    };
    let line = process_kill_result_to_line(result);

    insta::assert_json_snapshot!("process_kill_line", line);
}

#[test]
fn snapshot_spawn_target_line() {
    let line = spawn_target_to_line(
        1000,
        4242,
        &HashSet::from([1000, 4242, 4243]),
        &HashSet::from([4242]),
    );

    insta::assert_json_snapshot!("spawn_target_line", line);
}

#[test]
fn process_line_roundtrips_as_output_line() {
    let line = process_entry_to_line(process_entry());
    let json = serde_json::to_string(&line).expect("serialize");
    let back: OutputLine = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(line, back);
}
