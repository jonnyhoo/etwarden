//! # `output::schema`
//!
//! **Purpose**: Stable agent-contract serde types for NDJSON output.
//! **Public API**: `struct EventLine`, `struct DnsEventLine`, `struct HttpEventLine`, `struct TlsEventLine`, `struct SummaryLine`,
//!                `struct ErrorLine`, `enum OutputLine`, `fn event_to_line`,
//!                `fn event_to_line_enriched`
//! **Dependencies**: `parser::types`, `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 180

mod convert;
mod line;
mod scope;

pub use convert::{event_to_line, event_to_line_enriched};
pub use line::{
    DnsEventLine, ErrorLine, EventLine, HttpEventLine, OutputLine, SummaryLine, TlsEventLine,
};

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::Protocol;

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
