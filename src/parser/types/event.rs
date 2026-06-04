//! # `parser::types::event`
//!
//! **Purpose**: Defines parsed network event variants and common accessors.
//! **Public API**: `NetEvent`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 130 / 200

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

impl NetEvent {
    /// Returns the `bytes_out` field from any variant.
    #[must_use]
    pub const fn bytes_out(&self) -> u64 {
        match self {
            Self::Connect { bytes_out, .. }
            | Self::Disconnect { bytes_out, .. }
            | Self::Send { bytes_out, .. }
            | Self::Recv { bytes_out, .. } => *bytes_out,
            Self::RawCapture { .. }
            | Self::DnsQuery { .. }
            | Self::DnsResponse { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponse { .. }
            | Self::TlsHello { .. } => 0,
        }
    }

    /// Returns the `pid` field from any variant.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        match self {
            Self::Connect { pid, .. }
            | Self::Disconnect { pid, .. }
            | Self::Send { pid, .. }
            | Self::Recv { pid, .. }
            | Self::RawCapture { pid, .. }
            | Self::DnsQuery { pid, .. }
            | Self::DnsResponse { pid, .. }
            | Self::HttpRequest { pid, .. }
            | Self::HttpResponse { pid, .. }
            | Self::TlsHello { pid, .. } => *pid,
        }
    }

    /// Returns the `bytes_in` field from any variant.
    #[must_use]
    pub const fn bytes_in(&self) -> u64 {
        match self {
            Self::Connect { bytes_in, .. }
            | Self::Disconnect { bytes_in, .. }
            | Self::Send { bytes_in, .. }
            | Self::Recv { bytes_in, .. } => *bytes_in,
            Self::RawCapture { .. }
            | Self::DnsQuery { .. }
            | Self::DnsResponse { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponse { .. }
            | Self::TlsHello { .. } => 0,
        }
    }
}
