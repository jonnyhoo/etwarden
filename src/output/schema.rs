//! # `output::schema`
//!
//! **Purpose**: Stable agent-contract serde types for NDJSON output.
//! **Public API**: `struct EventLine`, `struct SummaryLine`, `enum OutputLine`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 130 / 200

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
#[must_use]
pub fn event_to_line(event: &NetEvent) -> EventLine {
    match *event {
        NetEvent::Connect {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => EventLine {
            timestamp,
            pid,
            proto,
            src: src.clone(),
            dst: dst.clone(),
            event: "connect".into(),
            bytes_out,
            bytes_in,
        },
        NetEvent::Disconnect {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => EventLine {
            timestamp,
            pid,
            proto,
            src: src.clone(),
            dst: dst.clone(),
            event: "disconnect".into(),
            bytes_out,
            bytes_in,
        },
        NetEvent::Send {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => EventLine {
            timestamp,
            pid,
            proto,
            src: src.clone(),
            dst: dst.clone(),
            event: "send".into(),
            bytes_out,
            bytes_in,
        },
        NetEvent::Recv {
            timestamp,
            pid,
            proto,
            ref src,
            ref dst,
            bytes_out,
            bytes_in,
        } => EventLine {
            timestamp,
            pid,
            proto,
            src: src.clone(),
            dst: dst.clone(),
            event: "recv".into(),
            bytes_out,
            bytes_in,
        },
        NetEvent::RawCapture { .. } => {
            unreachable!("RawCapture events are routed to pcap sink, not NDJSON")
        }
    }
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
        };
        let json = serde_json::to_string(&line).expect("serialize");
        assert!(
            json.contains("\"t\":\"2025-01-01T00:00:00Z\""),
            "actual: {json}"
        );
        assert!(json.contains("\"pid\":1234"), "actual: {json}");
        assert!(json.contains("\"proto\":\"TCP\""), "actual: {json}");
        assert!(json.contains("\"event\":\"connect\""), "actual: {json}");
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
        };
        let output = OutputLine::Event(line);
        let json = serde_json::to_string(&output).expect("serialize");
        let back: OutputLine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(output, back);
    }
}
