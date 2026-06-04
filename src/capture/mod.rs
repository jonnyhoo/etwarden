//! # `capture`
//!
//! **Purpose**: ETW session lifecycle — start, enable providers, consume events, stop.
//! **Public API**: `struct CaptureConfig`, `fn run_capture`
//! **Dependencies**: `parser`, `filter`, `output`, `error`, `pcap`, `chrono`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 93 / 120

pub mod event_loop;
pub mod provider;
pub mod session;
mod timestamp;

use std::sync::{atomic::AtomicBool, Arc};

use crate::{
    capture::{
        event_loop::run_event_loop,
        provider::{build_ndis_provider, build_tcpip_provider},
        session::EtwSession,
    },
    error::Result,
    filter::Filter,
    mitm::{start_mitm_proxy, MitmCaptureConfig, MitmProxyConfig},
    output::{schema::SummaryLine, Emitter},
    parser::ParserRegistry,
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
    /// Optional active HTTPS MITM proxy settings.
    pub mitm: Option<MitmCaptureConfig>,
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
    let emit_raw_capture = config.pcap_sink.is_some();
    let correlator = Arc::new(Correlator::new());
    let provider = build_tcpip_provider(Arc::clone(&registry), Some(Arc::clone(&correlator)));
    let ndis_provider = build_ndis_provider(
        Arc::clone(&registry),
        Arc::clone(&correlator),
        emit_raw_capture,
    );

    let mut session_builder = EtwSession::new();
    session_builder.add_provider(provider);
    session_builder.add_provider(ndis_provider);

    let running = session_builder.start()?;
    let mitm_handle = config
        .mitm
        .clone()
        .map(|mitm| {
            start_mitm_proxy(MitmProxyConfig {
                capture: mitm,
                target_pid: config.target_pid,
                registry: Arc::clone(&registry),
                correlator: Arc::clone(&correlator),
                stop_signal: config.stop_signal.clone(),
            })
        })
        .transpose()?;
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
    if let Some(handle) = mitm_handle {
        handle.stop()?;
    }

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
