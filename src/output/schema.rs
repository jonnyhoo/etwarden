//! # `output::schema`
//!
//! **Purpose**: Stable agent-contract serde types for NDJSON output.
//! **Public API**: `struct EventLine`, `struct DnsEventLine`, `struct SummaryLine`,
//!                `struct ErrorLine`, `enum OutputLine`, `fn event_to_line`,
//!                `fn event_to_line_enriched`
//! **Dependencies**: `parser::types`, `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 610 / 680

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    classify,
    parser::types::{NetEvent, Protocol},
};

/// A single NDJSON event line in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventLine {
    /// ISO 8601 timestamp.
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    /// Process ID that generated the event.
    pub pid: u32,
    /// Network protocol (`TCP` or `UDP`).
    pub proto: Protocol,
    /// Source address:port.
    pub src: String,
    /// Destination address:port.
    pub dst: String,
    /// Event type: `connect`, `disconnect`, `send`, `recv`.
    pub event: String,
    /// Bytes sent.
    pub bytes_out: u64,
    /// Bytes received.
    pub bytes_in: u64,
    /// IP scope of the remote address (e.g. `PUBLIC`, `PRIVATE`, `LOOPBACK`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Resolved process name (e.g. `chrome.exe`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// A DNS event line in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsEventLine {
    /// ISO 8601 timestamp.
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    /// Process ID that issued the DNS query.
    pub pid: u32,
    /// Event type: `dns_query` or `dns_response`.
    pub event: String,
    /// Queried domain name.
    #[serde(alias = "domain")]
    pub hostname: String,
    /// Numeric DNS record type (e.g. 1 = A, 28 = AAAA).
    pub query_type: u16,
    /// Human-readable DNS record type name (e.g. "A", "AAAA").
    pub query_type_name: String,
    /// DNS status code (response only, 0 for queries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u32>,
    /// Human-readable DNS status name (response only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_name: Option<String>,
    /// Resolved IP addresses from the response (response only).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub result_ips: Vec<String>,
    /// Whether the DNS response had the TC bit set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// Resolved process name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if predicates receive field references"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

/// The final summary line written on capture exit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryLine {
    /// Discriminator: always `"summary"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Monitored process ID.
    pub pid: u32,
    /// Capture duration in milliseconds.
    pub duration_ms: u64,
    /// Total connections observed.
    pub connections_total: u64,
    /// Total bytes sent.
    pub bytes_out_total: u64,
    /// Total bytes received.
    pub bytes_in_total: u64,
    /// Whether a pcapng file was written.
    pub pcap_written: bool,
}

/// A terminal error line written to stdout before returning an error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorLine {
    /// Discriminator: always `"error"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Human-readable error message.
    pub message: String,
}

impl ErrorLine {
    /// Creates an error line with the stable `type` discriminator.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: "error".into(),
            message: message.into(),
        }
    }
}

/// Top-level output line — event, DNS event, final summary, or terminal error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OutputLine {
    Event(EventLine),
    DnsEvent(DnsEventLine),
    Summary(SummaryLine),
    Error(ErrorLine),
}

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
        } => {
            let scope = scope_override.or_else(|| scope_from_addr(dst));
            OutputLine::Event(EventLine {
                timestamp,
                pid,
                proto,
                src: src.clone(),
                dst: dst.clone(),
                event: "connect".into(),
                bytes_out,
                bytes_in,
                scope,
                process_name,
            })
        }
        NetEvent::Disconnect {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => {
            let scope = scope_override.or_else(|| scope_from_addr(dst));
            OutputLine::Event(EventLine {
                timestamp,
                pid,
                proto,
                src: src.clone(),
                dst: dst.clone(),
                event: "disconnect".into(),
                bytes_out,
                bytes_in,
                scope,
                process_name,
            })
        }
        NetEvent::Send {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => {
            let scope = scope_override.or_else(|| scope_from_addr(dst));
            OutputLine::Event(EventLine {
                timestamp,
                pid,
                proto,
                src: src.clone(),
                dst: dst.clone(),
                event: "send".into(),
                bytes_out,
                bytes_in,
                scope,
                process_name,
            })
        }
        NetEvent::Recv {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => {
            let scope = scope_override.or_else(|| scope_from_addr(src));
            OutputLine::Event(EventLine {
                timestamp,
                pid,
                proto,
                src: src.clone(),
                dst: dst.clone(),
                event: "recv".into(),
                bytes_out,
                bytes_in,
                scope,
                process_name,
            })
        }
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

/// Classifies the remote address scope from an addr:port string.
fn scope_from_addr(addr: &str) -> Option<String> {
    let remote_ip = parse_ip_from_addr(addr)?;
    Some(classify::classify(remote_ip).label().to_string())
}

/// Extracts the IP portion from an `"addr:port"` string.
fn parse_ip_from_addr(addr: &str) -> Option<IpAddr> {
    // Handle IPv6 bracket format: [::1]:port
    if addr.starts_with('[') {
        let close = addr.find(']')?;
        if addr.get(close + 1..close + 2)? != ":" {
            return None;
        }
        addr.get(close + 2..)?.parse::<u16>().ok()?;
        let ip_str = &addr[1..close];
        return ip_str.parse().ok();
    }
    // IPv4: addr:port — split on last ':'
    let colon = addr.rfind(':')?;
    if addr[..colon].contains(':') {
        return None;
    }
    addr.get(colon + 1..)?.parse::<u16>().ok()?;
    let ip_str = &addr[..colon];
    ip_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    #[test]
    fn event_line_serializes_to_ndjson() {
        let line = EventLine {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            event: "connect".into(),
            bytes_out: 0,
            bytes_in: 0,
            scope: None,
            process_name: None,
        };
        let json = serde_json::to_string(&line).expect("serialize");
        assert!(
            json.contains("\"t\":\"2025-01-01T00:00:00Z\""),
            "actual: {json}"
        );
        assert!(json.contains("\"pid\":1234"), "actual: {json}");
        assert!(json.contains("\"proto\":\"TCP\""), "actual: {json}");
        assert!(json.contains("\"event\":\"connect\""), "actual: {json}");
        // Optional fields should not appear when None
        assert!(!json.contains("scope"), "actual: {json}");
        assert!(!json.contains("process_name"), "actual: {json}");
    }

    #[test]
    fn event_line_roundtrip() {
        let line = EventLine {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            event: "connect".into(),
            bytes_out: 0,
            bytes_in: 0,
            scope: None,
            process_name: None,
        };
        let json = serde_json::to_string(&line).expect("serialize");
        let back: EventLine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(line, back);
    }

    #[test]
    fn summary_line_serializes() {
        let summary = SummaryLine {
            kind: "summary".into(),
            pid: 1234,
            duration_ms: 10000,
            connections_total: 3,
            bytes_out_total: 1024,
            bytes_in_total: 8192,
            pcap_written: true,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(json.contains("\"type\":\"summary\""), "actual: {json}");
        assert!(json.contains("\"duration_ms\":10000"), "actual: {json}");
        assert!(json.contains("\"pcap_written\":true"), "actual: {json}");
    }

    #[test]
    fn summary_line_roundtrip() {
        let summary = SummaryLine {
            kind: "summary".into(),
            pid: 1234,
            duration_ms: 10000,
            connections_total: 3,
            bytes_out_total: 1024,
            bytes_in_total: 8192,
            pcap_written: false,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        let back: SummaryLine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(summary, back);
    }

    #[test]
    fn error_line_serializes() {
        let line = ErrorLine::new("capture failed");
        let json = serde_json::to_string(&line).expect("serialize");
        assert!(json.contains("\"type\":\"error\""), "actual: {json}");
        assert!(
            json.contains("\"message\":\"capture failed\""),
            "actual: {json}"
        );
    }

    #[test]
    fn output_line_error_roundtrip() {
        let output = OutputLine::Error(ErrorLine::new("capture failed"));
        let json = serde_json::to_string(&output).expect("serialize");
        let back: OutputLine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(output, back);
    }

    #[test]
    fn raw_capture_converts_to_error_line() {
        let event = NetEvent::RawCapture {
            frame: crate::parser::types::RawFrame {
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
    fn output_line_event_roundtrip() {
        let line = EventLine {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            event: "send".into(),
            bytes_out: 100,
            bytes_in: 0,
            scope: Some("PUBLIC".into()),
            process_name: Some("test.exe".into()),
        };
        let output = OutputLine::Event(line);
        let json = serde_json::to_string(&output).expect("serialize");
        let back: OutputLine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(output, back);
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
    fn scope_detects_private_address() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:49152".into(),
            dst: "10.0.0.1:80".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.scope, Some("PRIVATE".into()));
    }

    #[test]
    fn scope_detects_loopback() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "127.0.0.1:49152".into(),
            dst: "127.0.0.1:8080".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.scope, Some("LOOPBACK".into()));
    }

    #[test]
    fn recv_scope_uses_remote_source() {
        let event = NetEvent::Recv {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Udp,
            src: "8.8.8.8:53".into(),
            dst: "10.0.0.2:54321".into(),
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
    fn parse_ip_from_addr_handles_ipv6() {
        let ip = parse_ip_from_addr("[::1]:8080");
        assert_eq!(ip, Some(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));

        let ip = parse_ip_from_addr("192.168.1.1:443");
        assert_eq!(
            ip,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn parse_ip_from_addr_rejects_missing_or_invalid_port() {
        assert_eq!(parse_ip_from_addr("192.168.1.1:"), None);
        assert_eq!(parse_ip_from_addr("192.168.1.1:http"), None);
        assert_eq!(parse_ip_from_addr("[::1]"), None);
        assert_eq!(parse_ip_from_addr("[::1]:http"), None);
        assert_eq!(parse_ip_from_addr("::1:443"), None);
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
