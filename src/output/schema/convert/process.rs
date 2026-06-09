//! # `output::schema::convert::process`
//!
//! **Purpose**: Normalizes process metadata and process CLI results for schema projection.
//! **Public API**: module-private process enrichment helper plus process line converters
//! **Dependencies**: `process`, `output::schema::line`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 100 / 120

use std::collections::HashSet;

use crate::{
    output::schema::{OutputLine, ProcessKillLine, ProcessLine, SpawnTargetLine},
    process::{KillProcessResult, ProcessEntry, ProcessInfo},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ProcessFields {
    pub(super) name: Option<String>,
    pub(super) ppid: Option<u32>,
    pub(super) command_line: Option<String>,
    pub(super) tree_path: Option<String>,
}

impl ProcessFields {
    pub(super) fn from_name(name: Option<String>) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }

    pub(super) fn from_info(info: Option<ProcessInfo>) -> Self {
        let Some(info) = info else {
            return Self::default();
        };

        Self {
            name: Some(info.name),
            ppid: info.ppid,
            command_line: info.command_line,
            tree_path: Some(info.tree_path),
        }
    }
}

/// Converts a process inventory row into an NDJSON output line.
#[must_use]
pub fn process_entry_to_line(entry: ProcessEntry) -> OutputLine {
    OutputLine::Process(process_entry_line(entry))
}

/// Converts a process kill result into an NDJSON output line.
#[must_use]
pub fn process_kill_result_to_line(result: KillProcessResult) -> OutputLine {
    OutputLine::ProcessKill(ProcessKillLine {
        kind: "process_kill".into(),
        pid: result.pid,
        action: result.action,
        success: result.success,
        error: result.error,
        process: result.process.map(process_entry_line),
    })
}

/// Builds a spawn-target discovery NDJSON output line.
#[must_use]
pub fn spawn_target_to_line(
    root_pid: u32,
    primary_pid: u32,
    capture_pids: &HashSet<u32>,
    network_pids: &HashSet<u32>,
) -> OutputLine {
    OutputLine::SpawnTarget(SpawnTargetLine::new(
        root_pid,
        primary_pid,
        capture_pids.iter().copied().collect(),
        network_pids.iter().copied().collect(),
    ))
}

fn process_entry_line(entry: ProcessEntry) -> ProcessLine {
    ProcessLine {
        kind: "process".into(),
        pid: entry.pid,
        parent_pid: entry.parent_pid,
        name: entry.name,
        exe: entry.exe,
        command_line: entry.command_line,
        session_id: entry.session_id,
        current_session: entry.current_session,
        started_at_unix_secs: entry.started_at_unix_secs,
    }
}
