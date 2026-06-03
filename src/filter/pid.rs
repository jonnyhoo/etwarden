//! # `filter::pid`
//!
//! **Purpose**: PID allowlist filter — drops events not belonging to `TargetPid`.
//! **Public API**: `struct PidFilter`
//! **Dependencies**: `filter`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 78 / 200

use std::collections::HashSet;

use crate::{filter::Filter, parser::types::NetEvent};

/// Allows events only from specific PIDs.
pub struct PidFilter {
    allowed: HashSet<u32>,
}

impl PidFilter {
    /// Creates a new `PidFilter` allowing the given PIDs.
    ///
    /// # Arguments
    /// * `pids` — The set of allowed process IDs.
    #[must_use]
    pub const fn new(pids: HashSet<u32>) -> Self {
        Self { allowed: pids }
    }

    /// Creates a filter allowing a single PID.
    ///
    /// # Arguments
    /// * `pid` — The single allowed process ID.
    #[must_use]
    pub fn single(pid: u32) -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(pid);
        Self { allowed }
    }
}

impl Filter for PidFilter {
    fn allow(&self, event: &NetEvent) -> bool {
        let pid = extract_pid(event);
        self.allowed.contains(&pid)
    }
}

/// Extracts the PID from a `NetEvent`.
const fn extract_pid(event: &NetEvent) -> u32 {
    match event {
        NetEvent::Connect { pid, .. }
        | NetEvent::Disconnect { pid, .. }
        | NetEvent::Send { pid, .. }
        | NetEvent::Recv { pid, .. }
        | NetEvent::RawCapture { pid, .. } => *pid,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::{NetEvent, Protocol};

    fn test_timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    fn connect_event(pid: u32) -> NetEvent {
        NetEvent::Connect {
            timestamp: test_timestamp(),
            pid,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        }
    }

    #[test]
    fn single_pid_allows_matching() {
        let filter = PidFilter::single(1234);
        assert!(filter.allow(&connect_event(1234)));
    }

    #[test]
    fn single_pid_rejects_non_matching() {
        let filter = PidFilter::single(1234);
        assert!(!filter.allow(&connect_event(5678)));
    }

    #[test]
    fn multiple_pids_allowed() {
        let filter = PidFilter::new(HashSet::from([100, 200, 300]));
        assert!(filter.allow(&connect_event(100)));
        assert!(filter.allow(&connect_event(200)));
        assert!(!filter.allow(&connect_event(999)));
    }

    #[test]
    fn empty_set_blocks_all() {
        let filter = PidFilter::new(HashSet::new());
        assert!(!filter.allow(&connect_event(1234)));
    }

    #[test]
    fn works_with_disconnect_event() {
        let filter = PidFilter::single(42);
        let event = NetEvent::Disconnect {
            timestamp: test_timestamp(),
            pid: 42,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 512,
            bytes_in: 2048,
        };
        assert!(filter.allow(&event));
    }

    #[test]
    fn works_with_send_event() {
        let filter = PidFilter::single(42);
        let event = NetEvent::Send {
            timestamp: test_timestamp(),
            pid: 42,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 100,
            bytes_in: 0,
        };
        assert!(filter.allow(&event));
    }

    #[test]
    fn works_with_recv_event() {
        let filter = PidFilter::single(42);
        let event = NetEvent::Recv {
            timestamp: test_timestamp(),
            pid: 99,
            proto: Protocol::Udp,
            src: "93.184.216.34:443".into(),
            dst: "192.168.1.1:50234".into(),
            bytes_out: 0,
            bytes_in: 200,
        };
        assert!(!filter.allow(&event));
    }
}
