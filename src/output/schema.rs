//! # `output::schema`
//!
//! **Purpose**: Stable agent-contract serde types for NDJSON output.
//! **Public API**: `struct EventLine`, `struct DnsEventLine`, `struct HttpEventLine`, `struct TlsEventLine`,
//!                `struct RuleHitEventLine`, `struct ProcessLine`, `struct ProcessKillLine`,
//!                `struct SpawnTargetLine`, `struct SummaryLine`, `struct ErrorLine`,
//!                `enum OutputLine`, `fn event_to_line`, `fn event_to_line_enriched`,
//!                `fn process_entry_to_line`, `fn process_kill_result_to_line`,
//!                `fn spawn_target_to_line`
//! **Dependencies**: `parser::types`, `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 31 / 200

mod convert;
mod line;
mod scope;

pub use convert::{
    event_to_line, event_to_line_enriched, event_to_line_with_process_info, process_entry_to_line,
    process_kill_result_to_line, spawn_target_to_line,
};
pub use line::{
    DnsEventLine, ErrorLine, EventLine, HttpEventLine, HttpHeaderLine, HttpSseEventLine,
    OutputLine, ProcessKillLine, ProcessLine, RuleHitEventLine, SpawnTargetLine, SummaryLine,
    TlsEventLine, TunnelDataEventLine,
};

#[cfg(test)]
mod tests;
