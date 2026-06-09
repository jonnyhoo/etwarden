//! # `output::schema::convert`
//!
//! **Purpose**: Converts parser events into stable NDJSON schema lines.
//! **Public API**: `event_to_line`, `event_to_line_enriched`, `process_entry_to_line`,
//!   `process_kill_result_to_line`, `spawn_target_to_line`
//! **Dependencies**: `output::schema`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 82 / 120

mod dns;
mod dpi;
mod event;
mod http_payload;
mod network;
mod process;

use process::ProcessFields;
pub use process::{process_entry_to_line, process_kill_result_to_line, spawn_target_to_line};

use crate::{output::schema::OutputLine, parser::types::NetEvent, process::tree::ProcessInfo};

/// Converts a `NetEvent` into an `EventLine` for output.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
///
/// # Returns
/// An `OutputLine` ready for NDJSON serialization.
/// Enrichment fields (`scope`, `process_name`) are `None`.
#[must_use]
pub fn event_to_line(event: &NetEvent) -> OutputLine {
    event_to_line_enriched(event, None, None)
}

/// Converts a `NetEvent` into an enriched `OutputLine`.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
/// * `process_name` — Optional resolved process name.
/// * `scope_override` — Optional pre-computed scope label; if `None`,
///   scope is auto-detected from the remote address.
///
/// # Returns
/// An `OutputLine` with enrichment fields populated when available.
#[must_use]
pub fn event_to_line_enriched(
    event: &NetEvent,
    process_name: Option<String>,
    scope_override: Option<String>,
) -> OutputLine {
    event::event_to_line_enriched(
        event,
        ProcessFields::from_name(process_name),
        scope_override,
    )
}

/// Converts a `NetEvent` into an enriched `OutputLine` with process tree metadata.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
/// * `process_info` — Optional resolved process metadata.
/// * `scope_override` — Optional pre-computed scope label; if `None`,
///   scope is auto-detected from the remote address.
///
/// # Returns
/// An `OutputLine` with process enrichment fields populated when available.
#[must_use]
pub fn event_to_line_with_process_info(
    event: &NetEvent,
    process_info: Option<ProcessInfo>,
    scope_override: Option<String>,
) -> OutputLine {
    event::event_to_line_enriched(
        event,
        ProcessFields::from_info(process_info),
        scope_override,
    )
}

#[cfg(test)]
mod tests;
