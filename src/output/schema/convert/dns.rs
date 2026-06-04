//! # `output::schema::convert::dns`
//!
//! **Purpose**: Projects DNS parser events into stable NDJSON DNS schema lines.
//! **Public API**: module-private DNS projection helpers
//! **Dependencies**: `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 90

use chrono::{DateTime, Utc};

use super::process::ProcessFields;
use crate::output::schema::{DnsEventLine, OutputLine};

pub(super) fn dns_query_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    domain: &str,
    query_type: u16,
    query_type_name: &str,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    OutputLine::DnsEvent(DnsEventLine {
        timestamp,
        pid,
        event: "dns_query".into(),
        hostname: domain.to_owned(),
        query_type,
        query_type_name: query_type_name.to_owned(),
        status: None,
        status_name: None,
        result_ips: Vec::new(),
        truncated: false,
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "DNS response schema projection keeps source fields explicit"
)]
pub(super) fn dns_response_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    domain: &str,
    query_type: u16,
    query_type_name: &str,
    status: u32,
    status_name: &str,
    result_ips: &[String],
    truncated: bool,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    OutputLine::DnsEvent(DnsEventLine {
        timestamp,
        pid,
        event: "dns_response".into(),
        hostname: domain.to_owned(),
        query_type,
        query_type_name: query_type_name.to_owned(),
        status: Some(status),
        status_name: Some(status_name.to_owned()),
        result_ips: result_ips.to_vec(),
        truncated,
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}
