//! # `tracker`
//!
//! **Purpose**: Aggregates ETW network events into connection objects with state tracking,
//!   byte accounting, and DPI enrichment.
//! **Public API**: `struct ConnectionTracker`, `struct TrackedConnection`
//! **Dependencies**: `parser::types`, `parser::tcp_state`, `parser::dpi`, `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 400 / 460

mod endpoint;

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use crate::{
    parser::{
        dpi::{self, DpiResult},
        tcp_state::TcpState,
        types::{FiveTuple, NetEvent, Protocol},
    },
    tracker::endpoint::{classify_remote, parse_tuple_from_addrs},
};

/// Maximum number of active connections before new ones are dropped.
const DEFAULT_MAX_CONNECTIONS: usize = 65_536;

/// Default idle timeout before a connection is eligible for cleanup.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// TrackedConnection
// ---------------------------------------------------------------------------

/// A single tracked network connection aggregated from ETW events.
#[derive(Debug, Clone)]
pub struct TrackedConnection {
    /// Connection five-tuple (canonical key).
    pub tuple: FiveTuple,
    /// Owning process ID.
    pub pid: u32,
    /// Bytes sent (outgoing).
    pub bytes_out: u64,
    /// Bytes received (incoming).
    pub bytes_in: u64,
    /// TCP state machine state (only meaningful for TCP).
    pub tcp_state: TcpState,
    /// DPI result if a payload was inspected.
    pub dpi_result: Option<DpiResult>,
    /// IP scope classification of the remote endpoint.
    pub remote_scope: Option<&'static str>,
    /// First-seen timestamp.
    pub first_seen: SystemTime,
    /// Last-seen timestamp (updated on every event).
    pub last_seen: SystemTime,
}

impl TrackedConnection {
    /// Returns `true` if the connection is still active (not closed).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.tcp_state.is_closed()
    }

    /// Returns the idle duration since the last event.
    #[must_use]
    pub fn idle_duration(&self, now: SystemTime) -> Duration {
        now.duration_since(self.last_seen).unwrap_or(Duration::ZERO)
    }

    /// Returns `true` if this connection has been idle longer than the given timeout.
    #[must_use]
    pub fn is_stale(&self, now: SystemTime, timeout: Duration) -> bool {
        self.idle_duration(now) > timeout
    }
}

// ---------------------------------------------------------------------------
// ConnectionTracker
// ---------------------------------------------------------------------------

/// Thread-safe connection tracker that aggregates ETW events into connection objects.
pub struct ConnectionTracker {
    inner: Mutex<TrackerInner>,
}

struct TrackerInner {
    connections: HashMap<FiveTuple, TrackedConnection>,
    max_connections: usize,
    idle_timeout: Duration,
}

impl ConnectionTracker {
    /// Creates a new tracker with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DEFAULT_MAX_CONNECTIONS, DEFAULT_IDLE_TIMEOUT)
    }

    /// Creates a tracker with custom limits.
    #[must_use]
    pub fn with_config(max_connections: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(TrackerInner {
                connections: HashMap::new(),
                max_connections,
                idle_timeout,
            }),
        }
    }

    /// Ingests a `NetEvent`, creating or updating a tracked connection.
    ///
    /// Returns the updated connection snapshot if the event was tracked.
    pub fn ingest(&self, event: &NetEvent) -> Option<TrackedConnection> {
        let (tuple, pid, proto, bytes_out, bytes_in) = match event {
            NetEvent::Connect {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            }
            | NetEvent::Disconnect {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            }
            | NetEvent::Send {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            }
            | NetEvent::Recv {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            } => {
                let tuple = parse_tuple_from_addrs(src, dst, *proto)?;
                (tuple, *pid, *proto, *bytes_out, *bytes_in)
            }
            NetEvent::RawCapture { .. }
            | NetEvent::DnsQuery { .. }
            | NetEvent::DnsResponse { .. } => return None,
        };

        let now = SystemTime::now();
        let Ok(mut inner) = self.inner.lock() else {
            eprintln!("[etwarden] dropped tracker ingest: tracker lock poisoned");
            return None;
        };

        if !inner.connections.contains_key(&tuple)
            && inner.connections.len() >= inner.max_connections
        {
            return None;
        }

        let conn = inner
            .connections
            .entry(tuple.clone())
            .or_insert_with(|| TrackedConnection {
                tuple: tuple.clone(),
                pid,
                bytes_out: 0,
                bytes_in: 0,
                tcp_state: if proto == Protocol::Tcp {
                    TcpState::SynSent
                } else {
                    TcpState::Closed
                },
                dpi_result: None,
                remote_scope: classify_remote(&tuple),
                first_seen: now,
                last_seen: now,
            });

        // Update byte counters.
        conn.bytes_out = conn.bytes_out.saturating_add(bytes_out);
        conn.bytes_in = conn.bytes_in.saturating_add(bytes_in);
        conn.last_seen = now;

        // Update TCP state for disconnect events.
        if matches!(event, NetEvent::Disconnect { .. }) && proto == Protocol::Tcp {
            conn.tcp_state = TcpState::Closed;
        }

        Some(conn.clone())
    }

    /// Runs DPI on a payload for a given connection.
    pub fn apply_dpi(&self, tuple: &FiveTuple, payload: &[u8], src_port: u16, dst_port: u16) {
        let result = match tuple.protocol {
            Protocol::Tcp => dpi::analyze_tcp_payload(payload, src_port, dst_port),
            Protocol::Udp => dpi::analyze_udp_payload(payload, src_port, dst_port),
        };

        if let Some(dpi_result) = result {
            let Ok(mut inner) = self.inner.lock() else {
                eprintln!("[etwarden] dropped DPI enrichment: tracker lock poisoned");
                return;
            };
            if let Some(conn) = inner.connections.get_mut(tuple) {
                conn.dpi_result = Some(dpi_result);
            }
        }
    }

    /// Removes stale connections and returns them.
    pub fn cleanup(&self) -> Vec<TrackedConnection> {
        let Ok(mut inner) = self.inner.lock() else {
            eprintln!("[etwarden] skipped tracker cleanup: tracker lock poisoned");
            return Vec::new();
        };
        let now = SystemTime::now();
        let timeout = inner.idle_timeout;

        let stale_keys: Vec<FiveTuple> = inner
            .connections
            .iter()
            .filter(|(_, conn)| conn.is_stale(now, timeout) || !conn.is_active())
            .map(|(k, _)| k.clone())
            .collect();

        let mut removed = Vec::with_capacity(stale_keys.len());
        for key in stale_keys {
            if let Some(conn) = inner.connections.remove(&key) {
                removed.push(conn);
            }
        }
        removed
    }

    /// Returns a snapshot of all active connections.
    pub fn snapshot(&self) -> Vec<TrackedConnection> {
        let Ok(inner) = self.inner.lock() else {
            eprintln!("[etwarden] skipped tracker snapshot: tracker lock poisoned");
            return Vec::new();
        };
        inner.connections.values().cloned().collect()
    }

    /// Returns the number of tracked connections.
    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.lock() else {
            eprintln!("[etwarden] skipped tracker len: tracker lock poisoned");
            return 0;
        };
        inner.connections.len()
    }

    /// Returns `true` if no connections are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all tracked connections.
    pub fn clear(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            eprintln!("[etwarden] skipped tracker clear: tracker lock poisoned");
            return;
        };
        inner.connections.clear();
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::Protocol;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    fn connect_event(pid: u32, src: &str, dst: &str) -> NetEvent {
        NetEvent::Connect {
            timestamp: ts(),
            pid,
            proto: Protocol::Tcp,
            src: src.into(),
            dst: dst.into(),
            bytes_out: 0,
            bytes_in: 0,
        }
    }

    fn send_event(pid: u32, src: &str, dst: &str, bytes: u64) -> NetEvent {
        NetEvent::Send {
            timestamp: ts(),
            pid,
            proto: Protocol::Tcp,
            src: src.into(),
            dst: dst.into(),
            bytes_out: bytes,
            bytes_in: 0,
        }
    }

    fn disconnect_event(pid: u32, src: &str, dst: &str) -> NetEvent {
        NetEvent::Disconnect {
            timestamp: ts(),
            pid,
            proto: Protocol::Tcp,
            src: src.into(),
            dst: dst.into(),
            bytes_out: 0,
            bytes_in: 0,
        }
    }

    #[test]
    fn ingest_creates_connection() {
        let tracker = ConnectionTracker::new();
        let event = connect_event(42, "192.168.1.1:50234", "93.184.216.34:443");
        let conn = tracker.ingest(&event).expect("should create");
        assert_eq!(conn.pid, 42);
        assert_eq!(conn.bytes_out, 0);
        assert!(conn.remote_scope.is_some());
    }

    #[test]
    fn ingest_accumulates_bytes() {
        let tracker = ConnectionTracker::new();
        let src = "192.168.1.1:50234";
        let dst = "93.184.216.34:443";
        tracker.ingest(&connect_event(42, src, dst));
        tracker.ingest(&send_event(42, src, dst, 100));
        tracker.ingest(&send_event(42, src, dst, 200));

        let conns = tracker.snapshot();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].bytes_out, 300);
    }

    #[test]
    fn ingest_saturates_byte_counters() {
        let tracker = ConnectionTracker::new();
        let src = "192.168.1.1:50234";
        let dst = "93.184.216.34:443";
        tracker.ingest(&connect_event(42, src, dst));
        tracker.ingest(&send_event(42, src, dst, u64::MAX));
        tracker.ingest(&send_event(42, src, dst, 1));

        assert_eq!(tracker.snapshot()[0].bytes_out, u64::MAX);
    }

    #[test]
    fn disconnect_updates_tcp_state() {
        let tracker = ConnectionTracker::new();
        let src = "192.168.1.1:50234";
        let dst = "93.184.216.34:443";
        tracker.ingest(&connect_event(42, src, dst));
        tracker.ingest(&disconnect_event(42, src, dst));

        let conns = tracker.snapshot();
        assert_eq!(conns.len(), 1);
        assert!(conns[0].tcp_state.is_closed());
    }

    #[test]
    fn cleanup_removes_stale() {
        let tracker = ConnectionTracker::with_config(1000, Duration::from_millis(1));
        tracker.ingest(&connect_event(42, "192.168.1.1:50234", "93.184.216.34:443"));

        // Wait for idle timeout
        std::thread::sleep(Duration::from_millis(5));
        let removed = tracker.cleanup();
        assert_eq!(removed.len(), 1);
        assert!(tracker.is_empty());
    }

    #[test]
    fn raw_capture_ignored() {
        let tracker = ConnectionTracker::new();
        let event = NetEvent::RawCapture {
            frame: crate::parser::types::RawFrame {
                timestamp: ts(),
                data: vec![],
            },
            pid: 0,
        };
        assert!(tracker.ingest(&event).is_none());
    }

    #[test]
    fn distinct_flows_are_separate() {
        let tracker = ConnectionTracker::new();
        tracker.ingest(&connect_event(1, "10.0.0.1:1000", "10.0.0.2:80"));
        tracker.ingest(&connect_event(2, "10.0.0.1:1001", "10.0.0.2:80"));
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn capacity_limit_blocks_new_connections() {
        let tracker = ConnectionTracker::with_config(1, Duration::from_secs(300));
        let src = "10.0.0.1:1000";
        let dst = "10.0.0.2:80";
        assert!(tracker.ingest(&connect_event(1, src, dst)).is_some());
        assert!(tracker.ingest(&send_event(1, src, dst, 10)).is_some());
        assert!(tracker
            .ingest(&connect_event(2, "10.0.0.3:1001", "10.0.0.4:81"))
            .is_none());
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.snapshot()[0].bytes_out, 10);
    }
}
