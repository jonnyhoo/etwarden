//! # `output::schema`
//!
//! **Purpose**: Stable agent-contract serde types for NDJSON output.
//! **Public API**: `struct EventLine`, `struct SummaryLine`, `enum OutputLine`,
//!                `fn event_to_line`, `fn event_to_line_enriched`
//! **Dependencies**: `parser::types`, `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 180 / 250

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::classify;
use crate::parser::types::{NetEvent, Protocol};

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

/// Top-level output line — either an event or the final summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OutputLine {
    Event(EventLine),
    Summary(SummaryLine),
}

/// Converts a `NetEvent` into an `EventLine` for output.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
///
/// # Returns
/// An `EventLine` ready for NDJSON serialization.
/// Enrichment fields (`scope`, `process_name`) are `None`.
#[must_use]
pub fn event_to_line(event: &NetEvent) -> EventLine {
    event_to_line_enriched(event, None, None)
}

/// Converts a `NetEvent` into an enriched `EventLine`.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
/// * `process_name` — Optional resolved process name.
/// * `scope_override` — Optional pre-computed scope label; if `None`,
///   scope is auto-detected from the destination address.
///
/// # Returns
/// An `EventLine` with enrichment fields populated when available.
#[must_use]
pub fn event_to_line_enriched(
    event: &NetEvent,
    process_name: Option<String>,
    scope_override: Option<String>,
) -> EventLine {
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
            let scope = scope_override.or_else(|| scope_from_addrs(src, dst));
            EventLine {
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
            }
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
            let scope = scope_override.or_else(|| scope_from_addrs(src, dst));
            EventLine {
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
            }
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
            let scope = scope_override.or_else(|| scope_from_addrs(src, dst));
            EventLine {
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
            }
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
            let scope = scope_override.or_else(|| scope_from_addrs(src, dst));
            EventLine {
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
            }
        }
        NetEvent::RawCapture { .. } => {
            unreachable!("RawCapture events are routed to pcap sink, not NDJSON")
        }
    }
}

/// Classifies the remote address scope from src/dst strings.
///
/// Attempts to parse the "remote" side of a connection. For connect/send
/// events the remote is `dst`; for recv events the remote is `src`.
/// Falls back to `dst` if parsing fails.
fn scope_from_addrs(src: &str, dst: &str) -> Option<String> {
    let dst_ip = parse_ip_from_addr(dst);
    let src_ip = parse_ip_from_addr(src);

    // Prefer dst as remote (covers connect/send/recv from server perspective)
    let remote_ip = dst_ip.or(src_ip)?;
    Some(classify::classify(remote_ip).label().to_string())
}

/// Extracts the IP portion from an `"addr:port"` string.
fn parse_ip_from_addr(addr: &str) -> Option<IpAddr> {
    // Handle IPv6 bracket format: [::1]:port
    if addr.starts_with('[') {
        let close = addr.find(']')?;
        let ip_str = &addr[1..close];
        return ip_str.parse().ok();
    }
    // IPv4: addr:port — split on last ':'
    let colon = addr.rfind(':')?;
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
        assert_eq!(line.scope, Some("LOOPBACK".into()));
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
}
