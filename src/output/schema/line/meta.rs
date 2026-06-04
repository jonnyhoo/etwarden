//! # `output::schema::line::meta`
//!
//! **Purpose**: Stable summary/error/top-level NDJSON line types.
//! **Public API**: `SummaryLine`, `ErrorLine`, `OutputLine`
//! **Dependencies**: `output::schema::line::event`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 90

use serde::{Deserialize, Serialize};

use super::event::{DnsEventLine, EventLine, HttpEventLine, TlsEventLine};

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
