//! # `output::schema::convert::event::network`
//!
//! **Purpose**: Routes connection events to network schema projection.
//! **Public API**: module-private network event router
//! **Dependencies**: `output::schema::convert::network`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 90 / 140

use super::super::{network::network_event_line, process::ProcessFields};
use crate::{output::schema::OutputLine, parser::types::NetEvent};

pub(super) fn line(
    event: &NetEvent,
    process_fields: ProcessFields,
    scope_override: Option<String>,
) -> OutputLine {
    match *event {
        NetEvent::Connect {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => network_event_line(
            timestamp,
            pid,
            proto,
            src,
            dst,
            "connect",
            bytes_out,
            bytes_in,
            process_fields,
            scope_override,
        ),
        NetEvent::Disconnect {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => network_event_line(
            timestamp,
            pid,
            proto,
            src,
            dst,
            "disconnect",
            bytes_out,
            bytes_in,
            process_fields,
            scope_override,
        ),
        NetEvent::Send {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => network_event_line(
            timestamp,
            pid,
            proto,
            src,
            dst,
            "send",
            bytes_out,
            bytes_in,
            process_fields,
            scope_override,
        ),
        NetEvent::Recv {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => network_event_line(
            timestamp,
            pid,
            proto,
            src,
            dst,
            "recv",
            bytes_out,
            bytes_in,
            process_fields,
            scope_override,
        ),
        _ => super::unsupported_event_line(),
    }
}
