//! # `output::schema::convert::event::dns`
//!
//! **Purpose**: Routes DNS events to DNS schema projection.
//! **Public API**: module-private DNS event router
//! **Dependencies**: `output::schema::convert::dns`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 120

use super::super::{
    dns::{dns_query_line, dns_response_line},
    process::ProcessFields,
};
use crate::{output::schema::OutputLine, parser::types::NetEvent};

pub(super) fn line(event: &NetEvent, process_fields: ProcessFields) -> OutputLine {
    match *event {
        NetEvent::DnsQuery {
            timestamp,
            pid,
            ref domain,
            query_type,
            ref query_type_name,
        } => dns_query_line(
            timestamp,
            pid,
            domain,
            query_type,
            query_type_name,
            process_fields,
        ),
        NetEvent::DnsResponse {
            timestamp,
            pid,
            ref domain,
            query_type,
            ref query_type_name,
            status,
            ref status_name,
            ref result_ips,
            truncated,
        } => dns_response_line(
            timestamp,
            pid,
            domain,
            query_type,
            query_type_name,
            status,
            status_name,
            result_ips,
            truncated,
            process_fields,
        ),
        _ => super::unsupported_event_line(),
    }
}
