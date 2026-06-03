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
                if let Ok(mut events) = self.events.lock() {
                    events.push(event);
                }
                return true;
            }
        }
        false
    }

    /// Drains all buffered events.
    pub fn drain(&self) -> Vec<NetEvent> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |mut events| events.drain(..).collect())
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
