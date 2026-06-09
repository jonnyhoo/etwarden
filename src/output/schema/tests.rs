use chrono::{DateTime, Utc};

use super::*;
use crate::{
    parser::types::{NetEvent, Protocol},
    process::ProcessInfo,
};

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
        ppid: None,
        command_line: None,
        tree_path: None,
    };
    let json = serde_json::to_string(&line).expect("serialize");
    assert!(
        json.contains("\"t\":\"2025-01-01T00:00:00Z\""),
        "actual: {json}"
    );
    assert!(json.contains("\"pid\":1234"), "actual: {json}");
    assert!(json.contains("\"proto\":\"TCP\""), "actual: {json}");
    assert!(json.contains("\"event\":\"connect\""), "actual: {json}");
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
        ppid: None,
        command_line: None,
        tree_path: None,
    };
    let json = serde_json::to_string(&line).expect("serialize");
    let back: EventLine = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(line, back);
}

#[test]
fn summary_and_error_lines_serialize() {
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

    let line = ErrorLine::new("capture failed");
    let json = serde_json::to_string(&line).expect("serialize");
    assert!(json.contains("\"type\":\"error\""), "actual: {json}");
    assert!(
        json.contains("\"message\":\"capture failed\""),
        "actual: {json}"
    );
}

#[test]
fn output_lines_roundtrip() {
    let error = OutputLine::Error(ErrorLine::new("capture failed"));
    let json = serde_json::to_string(&error).expect("serialize");
    let back: OutputLine = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(error, back);

    let event = OutputLine::Event(EventLine {
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
        ppid: Some(1000),
        command_line: Some("test.exe --flag".into()),
        tree_path: Some("parent.exe(1000) → test.exe(1234)".into()),
    });
    let json = serde_json::to_string(&event).expect("serialize");
    let back: OutputLine = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, back);
}

#[test]
fn event_to_line_with_process_info_includes_tree_fields() {
    let event = NetEvent::Connect {
        timestamp: test_timestamp(),
        pid: 1234,
        proto: Protocol::Tcp,
        src: "192.168.1.1:50234".into(),
        dst: "93.184.216.34:443".into(),
        bytes_out: 0,
        bytes_in: 0,
    };
    let process = ProcessInfo {
        name: "chrome.exe".into(),
        ppid: Some(1000),
        command_line: Some("chrome.exe --type=renderer".into()),
        tree_path: "explorer.exe(1000) → chrome.exe(1234)".into(),
    };

    let line = event_to_line_with_process_info(&event, Some(process), None);
    let OutputLine::Event(line) = line else {
        unreachable!()
    };
    assert_eq!(line.process_name.as_deref(), Some("chrome.exe"));
    assert_eq!(line.ppid, Some(1000));
    assert_eq!(
        line.command_line.as_deref(),
        Some("chrome.exe --type=renderer")
    );
    assert_eq!(
        line.tree_path.as_deref(),
        Some("explorer.exe(1000) → chrome.exe(1234)")
    );
}
