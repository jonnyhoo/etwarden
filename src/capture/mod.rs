//! # `capture`
//!
//! **Purpose**: ETW session lifecycle — start, enable providers, consume events, stop.
//! **Public API**: `struct CaptureConfig`, `fn run_capture`
//! **Dependencies**: `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 70 / 80

pub mod event_loop;
pub mod provider;
pub mod session;

use std::sync::Arc;

use crate::{
    capture::{event_loop::run_event_loop, provider::build_tcpip_provider, session::EtwSession},
    error::Result,
    filter::Filter,
    output::{schema::SummaryLine, Emitter},
    parser::ParserRegistry,
};

/// Configuration for a capture session.
pub struct CaptureConfig {
    /// The process ID being monitored.
    pub target_pid: u32,
    /// Maximum capture duration. `None` = run until Ctrl+C.
    pub duration: Option<std::time::Duration>,
    /// Filters to apply before emitting events.
    pub filters: Vec<Box<dyn Filter>>,
    /// Output emitter for NDJSON lines.
    pub emitter: Box<dyn Emitter>,
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
pub fn run_capture(config: &mut CaptureConfig) -> Result<SummaryLine> {
    let registry = Arc::new(ParserRegistry::new());
    let provider = build_tcpip_provider(Arc::clone(&registry));

    let mut session_builder = EtwSession::new();
    session_builder.add_provider(provider);

    let running = session_builder.start()?;
    let summary = run_event_loop(running, &registry, &config.filters, config.emitter.as_mut())?;

    Ok(SummaryLine {
        kind: "summary".into(),
        pid: config.target_pid,
        duration_ms: 0,
        connections_total: summary.connections_total,
        bytes_out_total: summary.bytes_out_total,
        bytes_in_total: summary.bytes_in_total,
        pcap_written: false,
    })
}
