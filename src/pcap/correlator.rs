//! # `pcap::correlator`
//!
//! **Purpose**: Maps `FiveTuple` → PID for correlating NDIS frames with TCPIP events.
//! **Public API**: `struct Correlator`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 60 / 80

use std::{collections::HashMap, sync::Mutex};

use crate::parser::types::FiveTuple;

// ---------------------------------------------------------------------------
// Correlator
// ---------------------------------------------------------------------------

/// Thread-safe map from `FiveTuple` to PID.
///
/// TCPIP events call `register_connection` to populate the map.
/// NDIS events call `resolve_pid` to look up the owning process.
pub struct Correlator {
    map: Mutex<HashMap<FiveTuple, u32>>,
}

impl Correlator {
    /// Creates an empty correlator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a connection from a TCPIP event.
    pub fn register_connection(&self, pid: u32, tuple: FiveTuple) {
        if let Ok(mut map) = self.map.lock() {
            map.insert(tuple, pid);
        }
    }

    /// Resolves the PID for a given five-tuple.
    pub fn resolve_pid(&self, tuple: &FiveTuple) -> Option<u32> {
        self.map.lock().ok()?.get(tuple).copied()
    }

    /// Returns the number of registered connections.
    pub fn len(&self) -> usize {
        self.map.lock().map_or(0, |m| m.len())
    }

    /// Returns `true` if no connections are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::Protocol;

    fn tuple(src: &str, sport: u16, dst: &str, dport: u16) -> FiveTuple {
        FiveTuple {
            src_ip: src.into(),
            src_port: sport,
            dst_ip: dst.into(),
            dst_port: dport,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn register_and_resolve() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        corr.register_connection(42, t.clone());
        assert_eq!(corr.resolve_pid(&t), Some(42));
    }

    #[test]
    fn unknown_tuple_returns_none() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        assert_eq!(corr.resolve_pid(&t), None);
    }

    #[test]
    fn overwrite_updates_pid() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        corr.register_connection(42, t.clone());
        corr.register_connection(99, t.clone());
        assert_eq!(corr.resolve_pid(&t), Some(99));
    }

    #[test]
    fn len_and_is_empty() {
        let corr = Correlator::new();
        assert!(corr.is_empty());
        corr.register_connection(1, tuple("a", 1, "b", 2));
        assert_eq!(corr.len(), 1);
        assert!(!corr.is_empty());
    }
}
