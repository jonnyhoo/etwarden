//! # `output::schema::line::event`
//!
//! **Purpose**: Stable event NDJSON line types.
//! **Public API**: event NDJSON line structs
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 205 / 260

use chrono::{DateTime, Utc};
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
    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Process command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Parent→child process tree path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_path: Option<String>,
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
    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Process command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Parent→child process tree path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_path: Option<String>,
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
    /// Base64-encoded bounded HTTP headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_base64: Option<String>,
    /// Whether `headers_base64` was truncated by the capture limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub headers_truncated: bool,
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
    /// Whether the event came from active HTTPS MITM decryption.
    #[serde(default, skip_serializing_if = "is_false")]
    pub decrypted: bool,
    /// Original Content-Encoding header when the body stayed encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    /// Whether the captured body was decoded before serialization.
    #[serde(default, skip_serializing_if = "is_false")]
    pub decoded: bool,
    /// Base64-encoded bounded HTTP body bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    /// Whether `body_base64` was truncated by the capture limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub body_truncated: bool,
    /// Resolved process name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Process command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Parent→child process tree path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_path: Option<String>,
}

/// Bounded raw transparent tunnel data in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelDataEventLine {
    /// ISO 8601 timestamp.
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    /// Process ID that owned the tunnel.
    pub pid: u32,
    /// Event type: `tunnel_data`.
    pub event: String,
    /// Source address:port.
    pub src: String,
    /// Destination address:port.
    pub dst: String,
    /// Direction: `request` or `response`.
    pub direction: String,
    /// True when bytes are encrypted TLS/application data.
    pub encrypted: bool,
    /// Base64-encoded bounded request/response headers when plaintext HTTP is visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_base64: Option<String>,
    /// Whether `headers_base64` was truncated by the capture limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub headers_truncated: bool,
    /// Base64-encoded bounded payload bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_base64: Option<String>,
    /// Whether `payload_base64` was truncated by the capture limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub payload_truncated: bool,
    /// Total bytes seen in this first captured chunk.
    pub bytes_seen: u64,
    /// Total bytes emitted in this event.
    pub bytes_captured: u64,
    /// Resolved process name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Process command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Parent→child process tree path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_path: Option<String>,
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
    /// JA3 text fingerprint.
    pub ja3: String,
    /// JA3 MD5 hex digest.
    pub ja3_hash: String,
    /// JA3N text fingerprint with sorted extensions.
    pub ja3n: String,
    /// JA3N MD5 hex digest.
    pub ja3n_hash: String,
    /// JA4 fingerprint with sorted ciphers/extensions.
    pub ja4: String,
    /// JA4 original-order fingerprint.
    pub ja4o: String,
    /// JA4 raw sorted fingerprint.
    pub ja4r: String,
    /// JA4 raw original-order fingerprint.
    pub ja4ro: String,
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
    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Process command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Parent→child process tree path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_path: Option<String>,
}

/// A traffic-control rule hit event line in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleHitEventLine {
    /// Discriminator: always `"rule_hit"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// ISO 8601 timestamp.
    #[serde(rename = "t")]
    pub timestamp: DateTime<Utc>,
    /// Process ID associated with the traffic item.
    pub pid: u32,
    /// Rule category: `"replace"`, `"intercept"`, `"hosts"`, `"http_block"`, `"websocket_block"`.
    pub rule_type: String,
    /// Index of the matching rule within its category slice.
    pub rule_index: usize,
    /// Traffic direction: `"upstream"` or `"downstream"`.
    pub direction: String,
    /// Action taken: e.g. `"Replace"`, `"Drop"`, `"Disconnect"`, `"CloseRequest"`.
    pub action: String,
    /// Full request URL when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Resolved process name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

impl RuleHitEventLine {
    /// Creates a rule hit line with the stable `type` discriminator.
    #[must_use]
    pub fn new(
        pid: u32,
        rule_type: impl Into<String>,
        rule_index: usize,
        direction: impl Into<String>,
        action: impl Into<String>,
        url: Option<String>,
    ) -> Self {
        Self {
            kind: "rule_hit".into(),
            timestamp: chrono::Utc::now(),
            pid,
            rule_type: rule_type.into(),
            rule_index,
            direction: direction.into(),
            action: action.into(),
            url,
            process_name: None,
        }
    }
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if predicates receive field references"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}
