//! # `parser`
//!
//! **Purpose**: `EventParser` trait + type definitions for ETW event parsing.
//! **Public API**: `trait EventParser`, `struct ParserRegistry`, `mod types`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 38 / 80

pub mod dns;
pub mod dns_codes;
pub mod dpi;
pub(crate) mod endpoint;
pub mod ndis;
pub mod tcp_state;
pub mod tcpip;
pub mod types;

use std::sync::Mutex;

use windows::core::GUID;

use crate::parser::types::{NetEvent, RawEvent};

/// Parses `RawEvent` records from a specific ETW provider into `NetEvent`.
pub trait EventParser: Send + Sync {
    /// Returns the ETW provider GUID this parser handles.
    fn provider_guid(&self) -> GUID;

    /// Attempts to parse a raw ETW event into a structured `NetEvent`.
    ///
    /// # Arguments
    /// * `raw` — The raw event bytes and metadata from the ETW callback.
    ///
    /// # Returns
    /// `Some(NetEvent)` if the event was successfully parsed, `None` if not recognized.
    fn parse(&self, raw: &RawEvent) -> Option<NetEvent>;
}

/// Registry of `EventParser` impls, dispatching raw events to the correct parser.
pub struct ParserRegistry {
    parsers: Vec<Box<dyn EventParser>>,
    /// Buffer for parsed events, shared across ETW callbacks.
    events: Mutex<Vec<NetEvent>>,
}

impl ParserRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Registers a parser.
    pub fn register(&mut self, parser: Box<dyn EventParser>) {
        self.parsers.push(parser);
    }

    /// Dispatches a raw event to all registered parsers.
    ///
    /// # Returns
    /// `true` if any parser produced a `NetEvent`.
    pub fn dispatch(&self, raw: &RawEvent) -> bool {
        for parser in &self.parsers {
            if let Some(event) = parser.parse(raw) {
                return self.push_event(event);
            }
        }
        false
    }

    /// Pushes a parsed event into the shared buffer.
    pub fn push_event(&self, event: NetEvent) -> bool {
        let Ok(mut events) = self.events.lock() else {
            eprintln!("[etwarden] dropped parsed event: parser registry buffer lock poisoned");
            return false;
        };
        events.push(event);
        true
    }

    /// Drains all buffered events.
    pub fn drain(&self) -> Vec<NetEvent> {
        let Ok(mut events) = self.events.lock() else {
            eprintln!("[etwarden] dropped buffered events: parser registry buffer lock poisoned");
            return Vec::new();
        };
        events.drain(..).collect()
    }

    /// Returns a handle to the internal event buffer for direct pushing.
    pub const fn events_buffer(&self) -> &Mutex<Vec<NetEvent>> {
        &self.events
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::Protocol;

    struct AlwaysConnectParser;

    impl EventParser for AlwaysConnectParser {
        fn provider_guid(&self) -> GUID {
            GUID::zeroed()
        }

        fn parse(&self, raw: &RawEvent) -> Option<NetEvent> {
            Some(NetEvent::Connect {
                timestamp: raw.timestamp,
                pid: raw.pid,
                proto: Protocol::Tcp,
                src: "10.0.0.1:1234".into(),
                dst: "10.0.0.2:443".into(),
                bytes_out: 0,
                bytes_in: 0,
            })
        }
    }

    fn raw_event() -> RawEvent {
        RawEvent {
            event_id: 1,
            pid: 42,
            timestamp: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            data: Vec::new(),
        }
    }

    #[test]
    fn dispatch_uses_shared_push_path() {
        let mut registry = ParserRegistry::new();
        registry.register(Box::new(AlwaysConnectParser));

        assert!(registry.dispatch(&raw_event()));

        assert_eq!(registry.drain().len(), 1);
    }

    #[test]
    fn push_event_buffers_event() {
        let registry = ParserRegistry::new();
        let event = AlwaysConnectParser.parse(&raw_event()).expect("event");

        assert!(registry.push_event(event));

        assert_eq!(registry.drain().len(), 1);
    }
}
