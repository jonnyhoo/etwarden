//! # `capture::event_loop`
//!
//! **Purpose**: Main ETW event processing loop — drain, filter, emit.
//! **Public API**: `fn run_event_loop()`
//! **Dependencies**: `capture::session`, `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 80 / 100

use crate::capture::session::RunningSession;
use crate::error::Result;
use crate::filter::Filter;
use crate::output::schema::SummaryLine;
use crate::output::Emitter;
use crate::parser::ParserRegistry;

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
    mut emitter: Box<dyn Emitter>,
) -> Result<SummaryLine> {
    let mut connections_total: u64 = 0;
    let mut bytes_out_total: u64 = 0;
    let mut bytes_in_total: u64 = 0;

    // TODO: Replace with proper timed/signal-based loop in T19.
    // For now, drain once and stop — real implementation will poll
    // the registry on a timer until the session is signaled to stop.
    let events = registry.drain();

    for event in &events {
        // Apply all filters — event must pass every one.
        let passes = filters.iter().all(|f| f.allow(event));
        if !passes {
            continue;
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
        pcap_written: false,
    };
    // Summary emission will be handled in T19 integration wiring.
    // For now, just return the summary struct.

    session.stop()?;

    Ok(summary)
}
