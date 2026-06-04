//! # `output::schema`
//!
//! **Purpose**: Stable agent-contract serde types for NDJSON output.
//! **Public API**: `struct EventLine`, `struct DnsEventLine`, `struct HttpEventLine`, `struct TlsEventLine`, `struct SummaryLine`,
//!                `struct ErrorLine`, `enum OutputLine`, `fn event_to_line`,
//!                `fn event_to_line_enriched`
//! **Dependencies**: `parser::types`, `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 250 / 340

mod convert;
mod scope;

use chrono::{DateTime, Utc};
pub use convert::{event_to_line, event_to_line_enriched};
use serde::{Deserialize, Serialize};

use crate::parser::types::Protocol;

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

/// A plaintext HTTP DPI event line in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpEventLine {
    /// ISO 8601 timestamp.
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    /// Process ID that owned the packet.
    pub pid: u32,
    /// Event type: `http_request` or `http_response`.
    pub event: String,
    /// Source address:port.
    pub src: String,
    /// Destination address:port.
    pub dst: String,
    /// HTTP request method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// HTTP request path/URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// HTTP response status line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_line: Option<String>,
    /// HTTP version token.
    pub version: String,
    /// HTTP response status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// HTTP Host header value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Content-Type header value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Content-Length header value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// Resolved process name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// A TLS `ClientHello` DPI event line in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsEventLine {
    /// ISO 8601 timestamp.
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    /// Process ID that owned the packet.
    pub pid: u32,
    /// Event type: `tls_hello`.
    pub event: String,
    /// Source address:port.
    pub src: String,
    /// Destination address:port.
    pub dst: String,
    /// Server Name Indication hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// TLS version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// ALPN protocol list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// Number of cipher suites in the `ClientHello`.
    pub cipher_count: usize,
    /// Number of extensions in the `ClientHello`.
    pub extension_count: usize,
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
    HttpEvent(HttpEventLine),
    TlsEvent(TlsEventLine),
    Summary(SummaryLine),
    Error(ErrorLine),
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
}
