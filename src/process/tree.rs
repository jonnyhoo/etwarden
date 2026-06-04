//! # `process::tree`
//!
//! **Purpose**: Safe PID→process-tree enrichment via `sysinfo` snapshots.
//! **Public API**: `struct ProcessInfo`, `struct ProcessTreeCache`
//! **Dependencies**: `sysinfo`, `output::diagnostic`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 165 / 220

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    sync::Mutex,
    time::{Duration, Instant},
};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use crate::output::diagnostic;

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TREE_DEPTH_LIMIT: usize = 32;

/// Enriched process metadata captured from a process snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process name, e.g. `chrome.exe`.
    pub name: String,
    /// Parent PID when available.
    pub ppid: Option<u32>,
    /// Command line reconstructed from process arguments.
    pub command_line: Option<String>,
    /// Parent→child process tree path.
    pub tree_path: String,
}

/// Thread-safe cache mapping PID → process metadata and tree path.
pub struct ProcessTreeCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    entries: HashMap<u32, ProcessSnapshot>,
    last_refresh: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSnapshot {
    name: String,
    ppid: Option<u32>,
    command_line: Option<String>,
}

impl ProcessTreeCache {
    /// Creates a new cache with an initial process snapshot.
    #[must_use]
    pub fn new() -> Self {
        let mut inner = CacheInner {
            entries: HashMap::new(),
            last_refresh: Instant::now()
                .checked_sub(REFRESH_INTERVAL)
                .unwrap_or_else(Instant::now),
        };
        Self::do_refresh(&mut inner);

        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Returns process metadata and parent chain for a PID.
    #[must_use]
    pub fn get_info(&self, pid: u32) -> Option<ProcessInfo> {
        let Ok(mut guard) = self.inner.lock() else {
            diagnostic::warn(format_args!(
                "skipped process tree lookup: process tree cache lock poisoned"
            ));
            return None;
        };

        if guard.last_refresh.elapsed() > REFRESH_INTERVAL {
            Self::do_refresh(&mut guard);
        }

        process_info(pid, &guard.entries)
    }

    /// Force a refresh regardless of staleness.
    pub fn force_refresh(&self) {
        let Ok(mut guard) = self.inner.lock() else {
            diagnostic::warn(format_args!(
                "skipped process tree refresh: process tree cache lock poisoned"
            ));
            return;
        };
        Self::do_refresh(&mut guard);
    }

    fn do_refresh(cache: &mut CacheInner) {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
        );

        cache.entries.clear();
        for (pid, process) in sys.processes() {
            cache.entries.insert(
                pid.as_u32(),
                ProcessSnapshot {
                    name: process.name().to_string_lossy().to_string(),
                    ppid: process.parent().map(sysinfo::Pid::as_u32),
                    command_line: command_line(process.cmd()),
                },
            );
        }
        cache.last_refresh = Instant::now();
    }
}

impl Default for ProcessTreeCache {
    fn default() -> Self {
        Self::new()
    }
}

fn process_info(pid: u32, entries: &HashMap<u32, ProcessSnapshot>) -> Option<ProcessInfo> {
    let snapshot = entries.get(&pid)?;
    Some(ProcessInfo {
        name: snapshot.name.clone(),
        ppid: snapshot.ppid,
        command_line: snapshot.command_line.clone(),
        tree_path: tree_path(pid, entries),
    })
}

fn tree_path(pid: u32, entries: &HashMap<u32, ProcessSnapshot>) -> String {
    let mut lineage = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Some(pid);

    for _ in 0..TREE_DEPTH_LIMIT {
        let Some(current_pid) = current else {
            break;
        };
        if !seen.insert(current_pid) {
            break;
        }
        let Some(snapshot) = entries.get(&current_pid) else {
            break;
        };

        lineage.push((current_pid, snapshot.name.as_str()));
        current = snapshot.ppid;
    }

    let mut path = String::new();
    for (entry_pid, name) in lineage.into_iter().rev() {
        append_tree_part(&mut path, name, entry_pid);
    }
    path
}

fn append_tree_part(path: &mut String, name: &str, pid: u32) {
    if !path.is_empty() {
        path.push_str(" → ");
    }
    path.push_str(name);
    path.push('(');
    path.push_str(&pid.to_string());
    path.push(')');
}

fn command_line(parts: &[OsString]) -> Option<String> {
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
