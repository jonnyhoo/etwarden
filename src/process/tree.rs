//! # `process::tree`
//!
//! **Purpose**: Safe PID→process-tree enrichment via `sysinfo` snapshots.
//! **Public API**: `struct ProcessInfo`, `struct ProcessTreeCache`
//! **Dependencies**: `process::inventory`, `sysinfo`, `output::diagnostic`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 245 / 280

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use crate::{output::diagnostic, process::inventory};

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

    /// Returns all known descendants of `root_pid`, including `root_pid`.
    #[must_use]
    pub fn descendants_or_self(&self, root_pid: u32) -> HashSet<u32> {
        let Ok(mut guard) = self.inner.lock() else {
            diagnostic::warn(format_args!(
                "skipped process descendants lookup: process tree cache lock poisoned"
            ));
            return HashSet::from([root_pid]);
        };

        if guard.last_refresh.elapsed() > REFRESH_INTERVAL || !guard.entries.contains_key(&root_pid)
        {
            Self::do_refresh(&mut guard);
        }

        descendants_or_self(root_pid, &guard.entries)
    }

    /// Returns whether `pid` is `root_pid` or a descendant of it.
    #[must_use]
    pub fn is_descendant_or_self(&self, pid: u32, root_pid: u32) -> bool {
        if pid == root_pid {
            return true;
        }
        let Ok(mut guard) = self.inner.lock() else {
            diagnostic::warn(format_args!(
                "skipped process ancestry lookup: process tree cache lock poisoned"
            ));
            return false;
        };

        if guard.last_refresh.elapsed() > REFRESH_INTERVAL || !guard.entries.contains_key(&pid) {
            Self::do_refresh(&mut guard);
        }

        is_descendant_or_self(pid, root_pid, &guard.entries)
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
                    command_line: inventory::command_line(process.cmd()),
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

fn descendants_or_self(root_pid: u32, entries: &HashMap<u32, ProcessSnapshot>) -> HashSet<u32> {
    let mut descendants = HashSet::from([root_pid]);
    descendants.extend(
        entries
            .keys()
            .copied()
            .filter(|pid| is_descendant_or_self(*pid, root_pid, entries)),
    );
    descendants
}

fn is_descendant_or_self(pid: u32, root_pid: u32, entries: &HashMap<u32, ProcessSnapshot>) -> bool {
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
        current = entries.get(&current_pid).and_then(|snapshot| snapshot.ppid);
    }

    false
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

#[cfg(test)]
mod tests;
