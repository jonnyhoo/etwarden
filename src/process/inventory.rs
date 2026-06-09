//! # `process::inventory`
//!
//! **Purpose**: Canonical safe process snapshot, filtering, and tree selection.
//! **Public API**: `struct ProcessEntry`, `struct ProcessFilter`, `fn snapshot_processes`,
//!   `fn filtered_processes`, `fn process_tree`
//! **Dependencies**: `sysinfo`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 181 / 200

use std::{collections::HashSet, ffi::OsString};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

const TREE_DEPTH_LIMIT: usize = 32;

/// Stable process row used by CLI process commands and capture enrichment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID when available.
    pub parent_pid: Option<u32>,
    /// Executable image name.
    pub name: String,
    /// Full executable path when available.
    pub exe: Option<String>,
    /// Command line reconstructed from process arguments.
    pub command_line: Option<String>,
    /// Windows session ID when available.
    pub session_id: Option<u32>,
    /// Whether this process belongs to etwarden's current session.
    pub current_session: bool,
    /// Start time in Unix seconds. `0` means unavailable from provider.
    pub started_at_unix_secs: u64,
}

/// Process inventory filter. Name filters never imply termination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessFilter {
    /// Exact PID filter.
    pub pid: Option<u32>,
    /// Case-insensitive substring matched against name, exe, or command line.
    pub text: Option<String>,
    /// Include processes outside the current session.
    pub all_sessions: bool,
}

/// Captures a full process inventory snapshot.
#[must_use]
pub fn snapshot_processes() -> Vec<ProcessEntry> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );

    let current_session = sys
        .process(sysinfo::Pid::from_u32(std::process::id()))
        .and_then(|process| process.session_id())
        .map(sysinfo::Pid::as_u32);

    let mut entries: Vec<ProcessEntry> = sys
        .processes()
        .iter()
        .map(|(pid, process)| {
            let session_id = process.session_id().map(sysinfo::Pid::as_u32);
            ProcessEntry {
                pid: pid.as_u32(),
                parent_pid: process.parent().map(sysinfo::Pid::as_u32),
                name: process.name().to_string_lossy().to_string(),
                exe: process.exe().map(|path| path.display().to_string()),
                command_line: command_line(process.cmd()),
                session_id,
                current_session: current_session.is_none() || session_id == current_session,
                started_at_unix_secs: process.start_time(),
            }
        })
        .collect();
    entries.sort_by_key(|entry| entry.pid);
    entries
}

/// Captures and filters process inventory.
#[must_use]
pub fn filtered_processes(filter: &ProcessFilter) -> Vec<ProcessEntry> {
    filter_entries(snapshot_processes(), filter)
}

/// Captures one process tree, including `root_pid`.
#[must_use]
pub fn process_tree(root_pid: u32, all_sessions: bool) -> Vec<ProcessEntry> {
    let entries = snapshot_processes();
    let descendants = descendant_pids(root_pid, &entries);
    let filter = ProcessFilter {
        pid: None,
        text: None,
        all_sessions,
    };
    filter_entries(entries, &filter)
        .into_iter()
        .filter(|entry| descendants.contains(&entry.pid))
        .collect()
}

fn filter_entries(entries: Vec<ProcessEntry>, filter: &ProcessFilter) -> Vec<ProcessEntry> {
    entries
        .into_iter()
        .filter(|entry| filter.all_sessions || entry.current_session)
        .filter(|entry| filter.pid.is_none_or(|pid| entry.pid == pid))
        .filter(|entry| {
            filter
                .text
                .as_deref()
                .is_none_or(|needle| matches_text(entry, needle))
        })
        .collect()
}

fn matches_text(entry: &ProcessEntry, needle: &str) -> bool {
    let needle = needle.to_lowercase();
    contains_casefold(&entry.name, &needle)
        || entry
            .exe
            .as_deref()
            .is_some_and(|value| contains_casefold(value, &needle))
        || entry
            .command_line
            .as_deref()
            .is_some_and(|value| contains_casefold(value, &needle))
}

fn contains_casefold(value: &str, needle: &str) -> bool {
    value.to_lowercase().contains(needle)
}

fn descendant_pids(root_pid: u32, entries: &[ProcessEntry]) -> HashSet<u32> {
    entries
        .iter()
        .filter(|entry| is_descendant_or_self(entry.pid, root_pid, entries))
        .map(|entry| entry.pid)
        .collect()
}

fn is_descendant_or_self(pid: u32, root_pid: u32, entries: &[ProcessEntry]) -> bool {
    let mut seen = HashSet::new();
    let mut current = Some(pid);

    for _ in 0..TREE_DEPTH_LIMIT {
        let Some(current_pid) = current else {
            return false;
        };
        if current_pid == root_pid {
            return true;
        }
        if !seen.insert(current_pid) {
            return false;
        }
        current = entries
            .iter()
            .find(|entry| entry.pid == current_pid)
            .and_then(|entry| entry.parent_pid);
    }
    false
}

pub(crate) fn command_line(parts: &[OsString]) -> Option<String> {
    let mut command = String::new();
    for part in parts {
        if !command.is_empty() {
            command.push(' ');
        }
        command.push_str(&part.to_string_lossy());
    }

    if command.is_empty() {
        None
    } else {
        Some(command)
    }
}

#[cfg(test)]
mod tests;
