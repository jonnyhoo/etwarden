//! # `parser::correlation`
//!
//! **Purpose**: Parses Microsoft-Windows-Networking-Correlation ETW events,
//!   maintaining a map from `ActivityId` → `FiveTuple` for cross-provider correlation.
//! **Public API**: `struct CorrelationParser`, `struct ActivityMap`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 160

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use windows::core::GUID;

use crate::parser::{
    types::{FiveTuple, NetEvent, RawEvent},
    EventParser,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Microsoft-Windows-Networking-Correlation provider GUID.
pub const PROVIDER_CORRELATION: &str = "83ED54F0-4D48-4E45-B16E-726FFD1FA4AF";

// ---------------------------------------------------------------------------
// ActivityMap
// ---------------------------------------------------------------------------

/// Thread-safe shared map from `ActivityId` (GUID) to `FiveTuple`.
///
/// Populated by `CorrelationParser` from correlation ETW events.
/// Read by other parsers (e.g. `NdisParser`) to resolve activity IDs.
pub struct ActivityMap {
    map: Mutex<HashMap<[u8; 16], FiveTuple>>,
}

impl ActivityMap {
    /// Creates an empty activity map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Inserts a mapping from activity ID bytes to a five-tuple.
    pub fn insert(&self, activity_id: [u8; 16], tuple: FiveTuple) {
        if let Ok(mut map) = self.map.lock() {
            map.insert(activity_id, tuple);
        }
    }

    /// Looks up a five-tuple by activity ID bytes.
    pub fn get(&self, activity_id: &[u8; 16]) -> Option<FiveTuple> {
        self.map
            .lock()
            .ok()
            .and_then(|map| map.get(activity_id).cloned())
    }

    /// Returns the number of registered activity mappings.
    pub fn len(&self) -> usize {
        self.map.lock().map_or(0, |m| m.len())
    }

    /// Returns `true` if no activity mappings are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ActivityMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CorrelationParser
// ---------------------------------------------------------------------------

/// Parses ETW events from the Microsoft-Windows-Networking-Correlation provider.
///
/// Maintains the `ActivityMap` shared with other parsers for cross-provider
/// event correlation. This parser does not produce `NetEvent` output — it
/// returns `None` from `parse()` and only populates the activity map.
pub struct CorrelationParser {
    activity_map: Arc<ActivityMap>,
}

impl CorrelationParser {
    /// Creates a new `CorrelationParser` with the given activity map.
    #[must_use]
    pub const fn new(activity_map: Arc<ActivityMap>) -> Self {
        Self { activity_map }
    }

    /// Returns a reference to the shared activity map.
    #[must_use]
    pub const fn activity_map(&self) -> &Arc<ActivityMap> {
        &self.activity_map
    }
}

impl EventParser for CorrelationParser {
    fn provider_guid(&self) -> GUID {
        GUID::from(PROVIDER_CORRELATION)
    }

    fn parse(&self, _raw: &RawEvent) -> Option<NetEvent> {
        // Correlation events populate the activity map but do not produce
        // NetEvent output. Actual parsing will be implemented when the
        // correlation event schema is reverse-engineered.
        None
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
    fn provider_guid_matches() {
        let map = Arc::new(ActivityMap::new());
        let parser = CorrelationParser::new(map);
        let expected: GUID = GUID::from(PROVIDER_CORRELATION);
        assert_eq!(parser.provider_guid(), expected);
    }

    #[test]
    fn parse_returns_none() {
        let map = Arc::new(ActivityMap::new());
        let parser = CorrelationParser::new(map);
        let raw = RawEvent {
            event_id: 1,
            pid: 0,
            timestamp: chrono::Utc::now(),
            data: vec![],
        };
        assert!(parser.parse(&raw).is_none());
    }

    #[test]
    fn activity_map_insert_and_get() {
        let map = ActivityMap::new();
        let id = [0x01; 16];
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        map.insert(id, t.clone());
        let result = map.get(&id).expect("should find");
        assert_eq!(result, t);
    }

    #[test]
    fn activity_map_missing_returns_none() {
        let map = ActivityMap::new();
        let id = [0x02; 16];
        assert!(map.get(&id).is_none());
    }

    #[test]
    fn activity_map_len_and_is_empty() {
        let map = ActivityMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        map.insert([0x03; 16], tuple("1.2.3.4", 1, "5.6.7.8", 2));
        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
    }
}
