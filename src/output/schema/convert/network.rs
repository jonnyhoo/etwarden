//! # `output::schema::convert::network`
//!
//! **Purpose**: Projects connection parser events into stable NDJSON network schema lines.
//! **Public API**: module-private network projection helper
//! **Dependencies**: `output::schema`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 90

use chrono::{DateTime, Utc};

use super::process::ProcessFields;
use crate::{
    output::schema::{scope::scope_from_addr, EventLine, OutputLine},
    parser::types::Protocol,
};

#[expect(
    clippy::too_many_arguments,
    reason = "schema projection keeps fields explicit"
)]
pub(super) fn network_event_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    proto: Protocol,
    src: &str,
    dst: &str,
    event: &str,
    bytes_out: u64,
    bytes_in: u64,
    process_fields: ProcessFields,
    scope_override: Option<String>,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    OutputLine::Event(EventLine {
        timestamp,
        pid,
        proto,
        src: src.to_owned(),
        dst: dst.to_owned(),
        event: event.into(),
        bytes_out,
        bytes_in,
        scope: scope_override.or_else(|| scope_from_addr(dst)),
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}
