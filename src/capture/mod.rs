//! # `capture`
//!
//! **Purpose**: ETW session lifecycle — start, enable providers, consume events, stop.
//! **Public API**: `struct CaptureConfig`, `fn run_capture`
//! **Dependencies**: `parser`, `filter`, `output`, `error`, `pcap`, `chrono`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 185 / 200

pub mod event_loop;
pub mod provider;
pub mod session;
mod timestamp;

use std::{
    collections::HashSet,
    sync::{atomic::AtomicBool, Arc},
};

use crate::{
    capture::{
        event_loop::run_event_loop,
        provider::{build_ndis_provider, build_tcpip_provider},
        session::{EtwKernelSession, EtwSession, RunningSession},
    },
    divert::{start_divert, DivertConfig, RedirectMap},
    error::Result,
    filter::Filter,
    mitm::{start_mitm_proxy, MitmCaptureConfig, MitmProxyConfig},
    output::{diagnostic, schema::SummaryLine, Emitter},
    parser::{types::FiveTuple, ParserRegistry},
    pcap::{correlator::Correlator, PcapSink},
    process::current_tcp_connections_for_pid,
    rules::ruleset::RuleSet,
};

/// Configuration for a capture session.
pub struct CaptureConfig {
    /// The process ID being monitored.
    pub target_pid: u32,
    /// Process IDs used for startup TCP bootstrap.
    pub capture_pids: HashSet<u32>,
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
    /// Optional compiled traffic-control rules for the MITM proxy.
    pub rule_set: Option<Arc<RuleSet>>,
    /// Enable `WinDivert` TCP redirect for hot-attach MITM (requires `--pid` + MITM).
    pub enable_divert: bool,
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
/// Returns [`crate::error::EtwardenError`] if the ETW session fails.
pub fn run_capture(config: &mut CaptureConfig) -> Result<SummaryLine> {
    let registry = Arc::new(ParserRegistry::new());
    let emit_raw_capture = config.pcap_sink.is_some();
    let correlator = Arc::new(Correlator::new());
    let target_pids = bootstrap_pids(config.target_pid, &config.capture_pids);
    let existing_tcp_connections =
        bootstrap_existing_tcp_connections(&target_pids, correlator.as_ref());

    // Build TCPIP kernel provider — classic GUID with EnableFlags.
    let tcpip_provider = build_tcpip_provider(Arc::clone(&registry), Some(Arc::clone(&correlator)));

    // Build NDIS provider for user trace.
    let ndis_provider = build_ndis_provider(
        Arc::clone(&registry),
        Arc::clone(&correlator),
        emit_raw_capture,
    );

    // Kernel trace session — sets EVENT_TRACE_FLAG_NETWORK_TCPIP in EnableFlags.
    let mut kernel_session = EtwKernelSession::new();
    kernel_session.add_provider(tcpip_provider);
    let mut kernel_running = kernel_session.start()?;

    // User trace session — uses EnableTraceEx2 for NDIS provider.
    let mut user_session = EtwSession::new();
    user_session.add_provider(ndis_provider);
    let mut user_running = user_session.start()?;

    // Combine both into a single RunningSession.
    let (kernel_trace, _) = kernel_running.take_parts();
    let (_, user_trace) = user_running.take_parts();
    let running = RunningSession::new(kernel_trace, user_trace);

    let redirect_map = config.enable_divert.then(|| Arc::new(RedirectMap::new()));
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
                rule_set: config.rule_set.clone(),
                redirect_map: redirect_map.clone(),
            })
        })
        .transpose()?;

    // Start WinDivert redirect layer when MITM + divert enabled.
    let divert_handle = redirect_map
        .as_ref()
        .and_then(|map| {
            config.mitm.as_ref().map(|mitm| {
                start_divert(DivertConfig {
                    target_pids: target_pids.clone(),
                    proxy_addr: mitm.listen_addr,
                    redirect_map: Arc::clone(map),
                    existing_flows: existing_tcp_connections.clone(),
                    stop_signal: config.stop_signal.clone(),
                })
            })
        })
        .transpose()?;
    if divert_handle.is_some() {
        let pids: Vec<u32> = target_pids.iter().copied().collect();
        diagnostic::info(format_args!(
            "WinDivert redirect layer active for PIDs {pids:?}"
        ));
    }

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
    if let Some(handle) = divert_handle {
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

fn bootstrap_existing_tcp_connections(
    pids: &HashSet<u32>,
    correlator: &Correlator,
) -> Vec<FiveTuple> {
    let mut connections = Vec::new();
    for pid in pids {
        let tuples = match current_tcp_connections_for_pid(*pid) {
            Ok(tuples) => tuples,
            Err(err) => {
                diagnostic::warn(format_args!(
                    "skipped existing TCP bootstrap for PID {pid}: {err}"
                ));
                continue;
            }
        };
        for tuple in tuples {
            correlator.register_connection(*pid, tuple.clone());
            connections.push(tuple);
        }
    }
    connections
}

fn bootstrap_pids(target_pid: u32, capture_pids: &HashSet<u32>) -> HashSet<u32> {
    if capture_pids.is_empty() {
        HashSet::from([target_pid])
    } else {
        capture_pids.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_pids_falls_back_to_target_pid() {
        assert_eq!(bootstrap_pids(42, &HashSet::new()), HashSet::from([42]));
    }

    #[test]
    fn bootstrap_pids_uses_capture_pid_set() {
        assert_eq!(
            bootstrap_pids(42, &HashSet::from([42, 99])),
            HashSet::from([42, 99])
        );
    }
}
