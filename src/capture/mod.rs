//! # `capture`
//!
//! **Purpose**: ETW session lifecycle — start, enable providers, consume events, stop.
//! **Public API**: `struct CaptureConfig`, `fn run_capture`
//! **Dependencies**: `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 60 / 70

pub mod event_loop;
pub mod provider;
pub mod session;

use std::time::Duration;

use crate::error::EtwardenError;
use crate::filter::Filter;
use crate::output::schema::SummaryLine;
use crate::parser::ParserRegistry;

/// Configuration for a capture session.
pub struct CaptureConfig {
    /// The process ID being monitored.
    pub target_pid: u32,
    /// Maximum capture duration. `None` = run until Ctrl+C.
    pub duration: Option<Duration>,
    /// Parser registry for dispatching ETW events.
    pub parsers: ParserRegistry,
    /// Filters to apply before emitting events.
    pub filters: Vec<Box<dyn Filter>>,
}

/// Runs the capture loop with the given configuration.
///
/// # Arguments
/// * `config` — The capture configuration.
///
/// # Returns
/// A `SummaryLine` with aggregate capture statistics.
///
/// # Errors
/// Returns [`EtwardenError`] if the ETW session fails.
pub fn run_capture(config: &CaptureConfig) -> std::result::Result<SummaryLine, EtwardenError> {
    // T19 will implement the real ETW capture loop.
    Ok(SummaryLine {
        kind: "summary".into(),
        pid: config.target_pid,
        duration_ms: 0,
        connections_total: 0,
        bytes_out_total: 0,
        bytes_in_total: 0,
        pcap_written: false,
    })
}
