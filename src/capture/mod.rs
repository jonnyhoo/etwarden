//! # `capture`
//!
//! **Purpose**: ETW session lifecycle — start, enable providers, consume events, stop.
//! **Public API**: `struct CaptureConfig`, `fn run_capture`
//! **Dependencies**: `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 100 / 120

pub mod event_loop;
pub mod provider;
pub mod session;

use std::sync::{atomic::AtomicBool, Arc};

use crate::{
    capture::{
        event_loop::run_event_loop,
        provider::{
            build_correlation_provider, build_dns_client_provider, build_ndis_provider,
            build_tcpip_provider,
        },
        session::EtwSession,
    },
    error::Result,
    filter::Filter,
    output::{schema::SummaryLine, Emitter},
    parser::{correlation::ActivityMap, ParserRegistry},
    pcap::{correlator::Correlator, PcapSink},
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
    /// Optional pcap sink for raw frame capture.
    pub pcap_sink: Option<Box<dyn PcapSink>>,
    /// Optional external stop signal, used by `--spawn` child exit handling.
    pub stop_signal: Option<Arc<AtomicBool>>,
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
    let has_pcap = config.pcap_sink.is_some();
    let correlator = Arc::new(Correlator::new());
    let provider = build_tcpip_provider(Arc::clone(&registry), Some(Arc::clone(&correlator)));
    let dns_provider = build_dns_client_provider(Arc::clone(&registry));

    let mut session_builder = EtwSession::new();
    session_builder.add_provider(provider);
    session_builder.add_provider(dns_provider);

    // When pcap sink is present, enable NDIS + Correlation providers.
    if has_pcap {
        let activity_map = Arc::new(ActivityMap::new());
        let ndis_provider = build_ndis_provider(Arc::clone(&registry), Arc::clone(&correlator));
        let correlation_provider = build_correlation_provider(Arc::clone(&activity_map));
        session_builder.add_provider(ndis_provider);
        session_builder.add_provider(correlation_provider);
    }

    let running = session_builder.start()?;
    let summary = run_event_loop(
        running,
        &registry,
        &config.filters,
        config.emitter.as_mut(),
        config.pcap_sink.as_mut(),
        Some(correlator.as_ref()),
        config.duration,
        config.stop_signal.as_deref(),
    )?;

    Ok(SummaryLine {
        kind: "summary".into(),
        pid: config.target_pid,
        duration_ms: summary.duration_ms,
        connections_total: summary.connections_total,
        bytes_out_total: summary.bytes_out_total,
        bytes_in_total: summary.bytes_in_total,
        pcap_written: summary.pcap_written,
    })
}
