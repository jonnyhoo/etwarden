//! # `output::schema::convert`
//!
//! **Purpose**: Converts parser events into stable NDJSON schema lines.
//! **Public API**: `event_to_line`, `event_to_line_enriched`
//! **Dependencies**: `output::schema`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 215 / 280

use crate::{
    output::schema::{scope::scope_from_addr, DnsEventLine, ErrorLine, EventLine, OutputLine},
    parser::types::NetEvent,
};

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
            process_name,
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
            process_name,
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
            process_name,
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
            process_name,
            scope_override,
        ),
        NetEvent::RawCapture { .. } => OutputLine::Error(ErrorLine::new(
            "raw capture event cannot be serialized to NDJSON",
        )),
        NetEvent::DnsQuery {
            timestamp,
            pid,
            ref domain,
            query_type,
            ref query_type_name,
        } => OutputLine::DnsEvent(DnsEventLine {
            timestamp,
            pid,
            event: "dns_query".into(),
            hostname: domain.clone(),
            query_type,
            query_type_name: query_type_name.clone(),
            status: None,
            status_name: None,
            result_ips: Vec::new(),
            truncated: false,
            process_name,
        }),
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
        } => OutputLine::DnsEvent(DnsEventLine {
            timestamp,
            pid,
            event: "dns_response".into(),
            hostname: domain.clone(),
            query_type,
            query_type_name: query_type_name.clone(),
            status: Some(status),
            status_name: Some(status_name.clone()),
            result_ips: result_ips.clone(),
            truncated,
            process_name,
        }),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "schema projection keeps fields explicit"
)]
fn network_event_line(
    timestamp: chrono::DateTime<chrono::Utc>,
    pid: u32,
    proto: crate::parser::types::Protocol,
    src: &str,
    dst: &str,
    event: &str,
    bytes_out: u64,
    bytes_in: u64,
    process_name: Option<String>,
    scope_override: Option<String>,
) -> OutputLine {
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
        process_name,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::{Protocol, RawFrame};

    fn test_timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    #[test]
    fn raw_capture_converts_to_error_line() {
        let event = NetEvent::RawCapture {
            frame: RawFrame {
                timestamp: test_timestamp(),
                data: vec![0xde, 0xad, 0xbe, 0xef],
            },
            pid: 1234,
        };
        let line = event_to_line(&event);
        let OutputLine::Error(line) = line else {
            unreachable!()
        };
        assert_eq!(line.kind, "error");
        assert_eq!(
            line.message,
            "raw capture event cannot be serialized to NDJSON"
        );
    }

    #[test]
    fn event_to_line_converts_connect() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "connect");
        assert_eq!(line.pid, 1234);
    }

    #[test]
    fn event_to_line_converts_disconnect() {
        let event = NetEvent::Disconnect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 512,
            bytes_in: 2048,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "disconnect");
        assert_eq!(line.bytes_out, 512);
    }

    #[test]
    fn enriched_line_includes_scope() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "10.0.0.1:49152".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let line = event_to_line_enriched(&event, Some("chrome.exe".into()), None);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.scope, Some("PUBLIC".into()));
        assert_eq!(line.process_name, Some("chrome.exe".into()));
    }

    #[test]
    fn recv_scope_uses_remote_destination() {
        let event = NetEvent::Recv {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Udp,
            src: "10.0.0.2:54321".into(),
            dst: "8.8.8.8:53".into(),
            bytes_out: 0,
            bytes_in: 128,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.scope, Some("PUBLIC".into()));
    }

    #[test]
    fn dns_query_line_uses_hostname_field() {
        let event = NetEvent::DnsQuery {
            timestamp: test_timestamp(),
            pid: 1234,
            domain: "example.com".into(),
            query_type: 1,
            query_type_name: "A".into(),
        };
        let line = event_to_line(&event);
        let OutputLine::DnsEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.hostname, "example.com");
        assert_eq!(line.event, "dns_query");
        assert_eq!(line.status, None);
    }

    #[test]
    fn dns_response_line_keeps_status_and_ips() {
        let event = NetEvent::DnsResponse {
            timestamp: test_timestamp(),
            pid: 1234,
            domain: "example.com".into(),
            query_type: 1,
            query_type_name: "A".into(),
            status: 0,
            status_name: "NOERROR".into(),
            result_ips: vec!["93.184.216.34".into()],
            truncated: false,
        };
        let line = event_to_line(&event);
        let OutputLine::DnsEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.hostname, "example.com");
        assert_eq!(line.status, Some(0));
        assert_eq!(line.result_ips, vec!["93.184.216.34"]);
        assert!(!line.truncated);
    }

    #[test]
    fn dns_response_line_keeps_truncated_flag() {
        let event = NetEvent::DnsResponse {
            timestamp: test_timestamp(),
            pid: 1234,
            domain: "example.com".into(),
            query_type: 1,
            query_type_name: "A".into(),
            status: 0,
            status_name: "NOERROR".into(),
            result_ips: Vec::new(),
            truncated: true,
        };
        let line = event_to_line(&event);
        let OutputLine::DnsEvent(line) = line else {
            unreachable!()
        };
        assert!(line.truncated);
    }
}
