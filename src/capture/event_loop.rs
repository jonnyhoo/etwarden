//! # `capture::event_loop`
//!
//! **Purpose**: Main ETW event processing loop — drain, filter, emit.
//! **Public API**: `fn run_event_loop()`
//! **Dependencies**: `capture::session`, `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 101 / 240

mod drain;

#[cfg(test)]
mod tests;

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use self::drain::{drain_events, LoopStats};
use crate::{
    capture::session::RunningSession,
    error::Result,
    filter::Filter,
    output::{schema::SummaryLine, Emitter},
    parser::ParserRegistry,
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
/// Returns [`crate::error::EtwardenError`] on emission or session errors.
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
    let mut totals = LoopStats::default();
    let started = Instant::now();

    loop {
        let stats = drain_events(registry, filters, emitter, &mut pcap_sink, correlator)?;
        totals.merge(stats);

        if should_stop(started, duration, stop_signal) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let stop_result = session.stop();

    let stats = drain_events(registry, filters, emitter, &mut pcap_sink, correlator)?;
    totals.merge(stats);
    emitter.flush()?;
    stop_result?;

    Ok(SummaryLine {
        kind: "summary".into(),
        pid: 0, // Filled by caller.
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        connections_total: totals.connections_total,
        bytes_out_total: totals.bytes_out_total,
        bytes_in_total: totals.bytes_in_total,
        pcap_written: totals.pcap_written,
    })
}

fn should_stop(
    started: Instant,
    duration: Option<Duration>,
    stop_signal: Option<&AtomicBool>,
) -> bool {
    duration.is_some_and(|limit| started.elapsed() >= limit)
        || stop_signal.is_some_and(|signal| signal.load(Ordering::SeqCst))
}
