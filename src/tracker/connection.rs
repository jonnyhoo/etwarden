//! # `tracker::connection`
//!
//! **Purpose**: Defines public tracked connection snapshots.
//! **Public API**: `TrackedConnection`
//! **Dependencies**: `parser::types`, `parser::tcp_state`, `parser::dpi`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 100

use std::time::{Duration, SystemTime};

use crate::parser::{dpi::DpiResult, tcp_state::TcpState, types::FiveTuple};

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
