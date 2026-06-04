//! # `filter::tree`
//!
//! **Purpose**: Process-tree PID allowlist filter for spawned wrapper commands.
//! **Public API**: `struct ProcessTreeFilter`
//! **Dependencies**: `filter`, `parser::types`, `process`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 114 / 140

use std::{collections::HashSet, sync::Arc};

use crate::{filter::Filter, parser::types::NetEvent, process::ProcessTreeCache};

/// Allows events from a root PID and its discovered descendants.
pub struct ProcessTreeFilter {
    root_pid: u32,
    process_cache: Arc<ProcessTreeCache>,
    known_pids: std::sync::Mutex<HashSet<u32>>,
}

impl ProcessTreeFilter {
    /// Creates a process-tree filter rooted at `root_pid`.
    ///
    /// # Arguments
    /// * `root_pid` — Spawned wrapper/root process ID.
    /// * `process_cache` — Shared process-tree snapshot cache.
    /// * `initial_pids` — PIDs already known to belong to this tree.
    #[must_use]
    pub fn new(
        root_pid: u32,
        process_cache: Arc<ProcessTreeCache>,
        initial_pids: impl IntoIterator<Item = u32>,
    ) -> Self {
        let mut known_pids = HashSet::from([root_pid]);
        known_pids.extend(initial_pids);
        Self {
            root_pid,
            process_cache,
            known_pids: std::sync::Mutex::new(known_pids),
        }
    }
}

impl Filter for ProcessTreeFilter {
    fn allow(&self, event: &NetEvent) -> bool {
        let pid = event.pid();
        if self.is_known(pid) {
            return true;
        }
        if !self.process_cache.is_descendant_or_self(pid, self.root_pid) {
            return false;
        }
        self.remember(pid);
        true
    }
}

impl ProcessTreeFilter {
    fn is_known(&self, pid: u32) -> bool {
        self.known_pids
            .lock()
            .is_ok_and(|known| known.contains(&pid))
    }

    fn remember(&self, pid: u32) {
        if let Ok(mut known) = self.known_pids.lock() {
            known.insert(pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::{NetEvent, Protocol};

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    fn connect(pid: u32) -> NetEvent {
        NetEvent::Connect {
            timestamp: ts(),
            pid,
            proto: Protocol::Tcp,
            src: "127.0.0.1:50000".into(),
            dst: "127.0.0.1:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        }
    }

    #[test]
    fn allows_root_and_initial_pids() {
        let cache = Arc::new(ProcessTreeCache::new());
        let filter = ProcessTreeFilter::new(10, cache, [20, 30]);

        assert!(filter.allow(&connect(10)));
        assert!(filter.allow(&connect(20)));
        assert!(filter.allow(&connect(30)));
    }

    #[test]
    fn rejects_unknown_non_descendant_pid() {
        let cache = Arc::new(ProcessTreeCache::new());
        let filter = ProcessTreeFilter::new(9_999_990, cache, []);

        assert!(!filter.allow(&connect(9_999_991)));
    }
}
