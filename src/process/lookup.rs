//! # `process::lookup`
//!
//! **Purpose**: Safe PID→process-name resolution via `sysinfo`.
//! **Public API**: `struct ProcessNameCache`, `fn get_name(pid) -> Option<String>`
//! **Dependencies**: `sysinfo`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 80 / 150

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use sysinfo::ProcessesToUpdate;

/// Refresh interval for the process name cache.
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Thread-safe cache mapping PID → process name.
///
/// Uses `sysinfo::System` to enumerate running processes and extract
/// their names. Refreshes automatically when the cache is older than
/// [`REFRESH_INTERVAL`].
pub struct ProcessNameCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    /// PID → process name (e.g. `"chrome.exe"`).
    names: HashMap<u32, String>,
    /// Timestamp of last full refresh.
    last_refresh: Instant,
}

impl ProcessNameCache {
    /// Creates a new cache with an initial refresh.
    pub fn new() -> Self {
        let mut inner = CacheInner {
            names: HashMap::new(),
            last_refresh: Instant::now()
                .checked_sub(REFRESH_INTERVAL)
                .unwrap_or_else(Instant::now),
        };
        Self::do_refresh(&mut inner);

        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Returns the process name for a given PID.
    ///
    /// Triggers a background refresh if the cache is stale.
    pub fn get_name(&self, pid: u32) -> Option<String> {
        let Ok(mut guard) = self.inner.lock() else {
            eprintln!("[etwarden] skipped process name lookup: process cache lock poisoned");
            return None;
        };

        // Refresh if stale
        if guard.last_refresh.elapsed() > REFRESH_INTERVAL {
            Self::do_refresh(&mut guard);
        }

        guard.names.get(&pid).cloned()
    }

    /// Force a refresh regardless of staleness.
    pub fn force_refresh(&self) {
        let Ok(mut guard) = self.inner.lock() else {
            eprintln!("[etwarden] skipped process cache refresh: process cache lock poisoned");
            return;
        };
        Self::do_refresh(&mut guard);
    }

    fn do_refresh(cache: &mut CacheInner) {
        let mut sys = sysinfo::System::new();
        // Only refresh process list, skip CPU/memory for speed
        sys.refresh_processes(ProcessesToUpdate::All, true);

        cache.names.clear();
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name().to_string_lossy().to_string();
            cache.names.insert(pid_u32, name);
        }
        cache.last_refresh = Instant::now();
    }
}

impl Default for ProcessNameCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn cache_returns_current_process_name() {
        let cache = ProcessNameCache::new();
        let my_pid = std::process::id();
        let name = cache.get_name(my_pid);
        assert!(name.is_some(), "should find current process");
        let name = name.unwrap_or_default();
        assert!(!name.is_empty(), "process name should not be empty");
    }

    #[test]
    fn cache_returns_none_for_bogus_pid() {
        let cache = ProcessNameCache::new();
        let result = cache.get_name(9_999_999);
        assert!(result.is_none(), "bogus PID should return None");
    }

    #[test]
    fn default_works() {
        let _cache = ProcessNameCache::default();
    }

    #[test]
    fn poisoned_cache_lock_returns_none_and_refresh_noops() {
        let cache = Arc::new(ProcessNameCache::new());
        let poisoned = Arc::clone(&cache);
        let handle = std::thread::spawn(move || {
            let _guard = poisoned.inner.lock().expect("lock process cache");
            std::panic::resume_unwind(Box::new("poison process cache lock"));
        });

        assert!(handle.join().is_err());
        assert!(cache.get_name(std::process::id()).is_none());
        cache.force_refresh();
    }
}
