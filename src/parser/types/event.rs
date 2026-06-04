//! # `parser::types::event`
//!
//! **Purpose**: Defines parsed network event variants and common accessors.
//! **Public API**: `NetEvent`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 130 / 200

mod accessors;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{Protocol, RawFrame};

/// A single parsed network event produced by ETW providers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NetEvent {
    Connect {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    Disconnect {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    Send {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    Recv {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    /// Raw frame from NDIS provider — routed to pcap sink, not NDJSON.
    RawCapture { frame: RawFrame, pid: u32 },
    /// DNS query observed from an attributed ETW source.
    DnsQuery {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        domain: String,
        query_type: u16,
        query_type_name: String,
    },
    /// DNS response observed from an attributed ETW source.
    DnsResponse {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        domain: String,
        query_type: u16,
        query_type_name: String,
        status: u32,
        status_name: String,
        result_ips: Vec<String>,
        truncated: bool,
    },
    /// Plaintext HTTP request observed from an attributed TCP packet.
    HttpRequest {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        src: String,
        dst: String,
        method: String,
        path: String,
        host: Option<String>,
        version: String,
        content_type: Option<String>,
        content_length: Option<u64>,
    },
    /// Plaintext HTTP response observed from an attributed TCP packet.
    HttpResponse {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        src: String,
        dst: String,
        status_line: String,
        host: Option<String>,
        version: String,
        status_code: u16,
        content_type: Option<String>,
        content_length: Option<u64>,
    },
    /// TLS `ClientHello` metadata observed from an attributed TCP packet.
    TlsHello {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        src: String,
        dst: String,
        sni: Option<String>,
        version: Option<String>,
        alpn: Vec<String>,
        cipher_count: usize,
        extension_count: usize,
    },
}
