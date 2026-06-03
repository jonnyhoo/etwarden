//! # `capture::event_loop`
//!
//! **Purpose**: Main ETW event processing loop — drain, filter, emit.
//! **Public API**: `fn run_event_loop()`
//! **Dependencies**: `capture::session`, `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 100 / 120

use crate::{
    capture::session::RunningSession,
    error::Result,
    filter::Filter,
    output::{schema::SummaryLine, Emitter},
    parser::{types::NetEvent, ParserRegistry},
    pcap::{correlator::Correlator, PcapSink},
};

// ---------------------------------------------------------------------------
// run_event_loop
// ---------------------------------------------------------------------------

/// Runs the main event processing loop.
///
/// Drains events from the `ParserRegistry`, applies filters, and emits
/// matching events via the `Emitter`. Blocks until the session is stopped
/// (typically from another thread or Ctrl+C handler).
///
/// # Arguments
/// * `session` — The running ETW trace session.
/// * `registry` — Shared parser registry with buffered events.
/// * `filters` — Filters to apply; events must pass ALL filters.
/// * `emitter` — Output emitter for NDJSON lines.
///
/// # Returns
/// A `SummaryLine` with aggregate statistics.
///
/// # Errors
/// Returns [`EtwardenError`] on emission or session errors.
pub fn run_event_loop(
    mut session: RunningSession,
    registry: &ParserRegistry,
    filters: &[Box<dyn Filter>],
    emitter: &mut dyn Emitter,
    mut pcap_sink: Option<&mut Box<dyn PcapSink>>,
    correlator: Option<&Correlator>,
) -> Result<SummaryLine> {
    let mut connections_total: u64 = 0;
    let mut bytes_out_total: u64 = 0;
    let mut bytes_in_total: u64 = 0;
    let mut pcap_written = false;

    // TODO: Replace with proper timed/signal-based loop in T19.
    // For now, drain once and stop — real implementation will poll
    // the registry on a timer until the session is signaled to stop.
    let events = registry.drain();

    for event in &events {
        // Route RawCapture to pcap sink, not emitter.
        if let NetEvent::RawCapture { frame, pid } = event {
            if let Some(sink) = pcap_sink.as_mut() {
                sink.write_frame(frame, *pid)?;
                pcap_written = true;
            }
            continue;
        }

        // Apply all filters — event must pass every one.
        let passes = filters.iter().all(|f| f.allow(event));
        if !passes {
            continue;
        }

        // Register Connect events in the correlator for NDIS PID resolution.
        if let (
            Some(corr),
            NetEvent::Connect {
                pid,
                proto,
                src,
                dst,
                ..
            },
        ) = (correlator, event)
        {
            if let Some(tuple) = parse_tuple_from_event(*pid, src, dst, *proto) {
                corr.register_connection(*pid, tuple);
            }
        }

        emitter.emit(event)?;
        connections_total += 1;
        bytes_out_total += event.bytes_out();
        bytes_in_total += event.bytes_in();
    }

    // Emit summary
    let summary = SummaryLine {
        kind: "summary".into(),
        pid: 0, // Will be filled by caller
        duration_ms: 0,
        connections_total,
        bytes_out_total,
        bytes_in_total,
        pcap_written,
    };

    session.stop()?;

    Ok(summary)
}

/// Parse a `FiveTuple` from a Connect event's address strings.
fn parse_tuple_from_event(
    _pid: u32,
    src: &str,
    dst: &str,
    proto: crate::parser::types::Protocol,
) -> Option<crate::parser::types::FiveTuple> {
    use crate::parser::types::FiveTuple;

    let (src_ip, src_port) = parse_addr_port(src)?;
    let (dst_ip, dst_port) = parse_addr_port(dst)?;
    Some(FiveTuple {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: proto,
    })
}

/// Split "ip:port" into (`ip_string`, `port_u16`).
fn parse_addr_port(addr: &str) -> Option<(String, u16)> {
    // Handle IPv6 bracket notation: [::1]:443
    if let Some(close) = addr.find(']') {
        let ip = addr[1..close].to_string();
        let port_str = addr.get(close + 2..)?;
        let port = port_str.parse().ok()?;
        return Some((ip, port));
    }
    // IPv4: 192.168.1.1:443
    let colon = addr.rfind(':')?;
    let ip = addr[..colon].to_string();
    let port = addr[colon + 1..].parse().ok()?;
    Some((ip, port))
}
