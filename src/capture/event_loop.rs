//! # `capture::event_loop`
//!
//! **Purpose**: Main ETW event processing loop — drain, filter, emit.
//! **Public API**: `fn run_event_loop()`
//! **Dependencies**: `capture::session`, `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 160 / 180

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

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
    duration: Option<Duration>,
    stop_signal: Option<&AtomicBool>,
) -> Result<SummaryLine> {
    let mut connections_total: u64 = 0;
    let mut bytes_out_total: u64 = 0;
    let mut bytes_in_total: u64 = 0;
    let mut pcap_written = false;
    let started = Instant::now();

    loop {
        let stats = drain_events(registry, filters, emitter, &mut pcap_sink, correlator)?;
        connections_total += stats.connections_total;
        bytes_out_total += stats.bytes_out_total;
        bytes_in_total += stats.bytes_in_total;
        pcap_written |= stats.pcap_written;

        if should_stop(started, duration, stop_signal) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    session.stop()?;

    let stats = drain_events(registry, filters, emitter, &mut pcap_sink, correlator)?;
    connections_total += stats.connections_total;
    bytes_out_total += stats.bytes_out_total;
    bytes_in_total += stats.bytes_in_total;
    pcap_written |= stats.pcap_written;
    emitter.flush()?;

    Ok(SummaryLine {
        kind: "summary".into(),
        pid: 0, // Filled by caller.
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        connections_total,
        bytes_out_total,
        bytes_in_total,
        pcap_written,
    })
}

struct LoopStats {
    connections_total: u64,
    bytes_out_total: u64,
    bytes_in_total: u64,
    pcap_written: bool,
}

fn drain_events(
    registry: &ParserRegistry,
    filters: &[Box<dyn Filter>],
    emitter: &mut dyn Emitter,
    pcap_sink: &mut Option<&mut Box<dyn PcapSink>>,
    correlator: Option<&Correlator>,
) -> Result<LoopStats> {
    let mut stats = LoopStats {
        connections_total: 0,
        bytes_out_total: 0,
        bytes_in_total: 0,
        pcap_written: false,
    };
    let events = registry.drain();
    for event in &events {
        // Route RawCapture to pcap sink, not emitter.
        if let NetEvent::RawCapture { frame, pid } = event {
            if let Some(sink) = pcap_sink.as_mut() {
                sink.write_frame(frame, *pid)?;
                stats.pcap_written = true;
            }
            continue;
        }

        // Apply all filters — event must pass every one.
        let passes = filters.iter().all(|f| f.allow(event));
        if !passes {
            continue;
        }

        if let Some(corr) = correlator {
            corr.register_event(event);
        }

        emitter.emit(event)?;
        stats.connections_total += 1;
        stats.bytes_out_total += event.bytes_out();
        stats.bytes_in_total += event.bytes_in();
    }
    Ok(stats)
}

fn should_stop(
    started: Instant,
    duration: Option<Duration>,
    stop_signal: Option<&AtomicBool>,
) -> bool {
    duration.is_some_and(|limit| started.elapsed() >= limit)
        || stop_signal.is_some_and(|signal| signal.load(Ordering::SeqCst))
}
