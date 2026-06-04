//! # `output::schema::convert::event`
//!
//! **Purpose**: Dispatches parser events to schema projection helpers.
//! **Public API**: module-private event projection router
//! **Dependencies**: `output::schema`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 140 / 200

mod dns;
mod dpi;
mod network;

use super::process::ProcessFields;
use crate::{
    output::schema::{ErrorLine, OutputLine},
    parser::types::NetEvent,
};

fn unsupported_event_line() -> OutputLine {
    OutputLine::Error(ErrorLine::new(
        "unsupported event cannot be serialized to NDJSON",
    ))
}

pub(super) fn event_to_line_enriched(
    event: &NetEvent,
    process_fields: ProcessFields,
    scope_override: Option<String>,
) -> OutputLine {
    match event {
        NetEvent::Connect { .. }
        | NetEvent::Disconnect { .. }
        | NetEvent::Send { .. }
        | NetEvent::Recv { .. } => network::line(event, process_fields, scope_override),
        NetEvent::RawCapture { .. } => OutputLine::Error(ErrorLine::new(
            "raw capture event cannot be serialized to NDJSON",
        )),
        NetEvent::DnsQuery { .. } | NetEvent::DnsResponse { .. } => {
            dns::line(event, process_fields)
        }
        NetEvent::HttpRequest { .. }
        | NetEvent::DecryptedHttpRequest { .. }
        | NetEvent::HttpResponse { .. }
        | NetEvent::DecryptedHttpResponse { .. }
        | NetEvent::TlsHello { .. } => dpi::line(event, process_fields),
    }
}
