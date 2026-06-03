//! # `schema_compat`
//!
//! **Purpose**: Snapshot tests for every `OutputLine` variant via insta.
//!              These snapshots are the schema regression guard.
//! **Public API**: (integration test)
//! **Dependencies**: `etwarden`, `insta`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 100 / 150

use chrono::{TimeZone, Utc};
use etwarden::output::schema::{event_to_line, OutputLine, SummaryLine};
use etwarden::parser::types::{NetEvent, Protocol};

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn connect_event() -> NetEvent {
    NetEvent::Connect {
        timestamp: ts(),
        pid: 1234,
        proto: Protocol::Tcp,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:443".into(),
        bytes_out: 1024,
        bytes_in: 4096,
    }
}

fn disconnect_event() -> NetEvent {
    NetEvent::Disconnect {
        timestamp: ts(),
        pid: 1234,
        proto: Protocol::Tcp,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:443".into(),
        bytes_out: 2048,
        bytes_in: 8192,
    }
}

fn send_event() -> NetEvent {
    NetEvent::Send {
        timestamp: ts(),
        pid: 5678,
        proto: Protocol::Udp,
        src: "10.0.0.2:54321".into(),
        dst: "8.8.8.8:53".into(),
        bytes_out: 64,
        bytes_in: 0,
    }
}

fn recv_event() -> NetEvent {
    NetEvent::Recv {
        timestamp: ts(),
        pid: 5678,
        proto: Protocol::Udp,
        src: "8.8.8.8:53".into(),
        dst: "10.0.0.2:54321".into(),
        bytes_out: 0,
        bytes_in: 128,
    }
}

#[test]
fn snapshot_connect_event_line() {
    let line = event_to_line(&connect_event());
    insta::assert_json_snapshot!("connect_event_line", line);
}

#[test]
fn snapshot_disconnect_event_line() {
    let line = event_to_line(&disconnect_event());
    insta::assert_json_snapshot!("disconnect_event_line", line);
}

#[test]
fn snapshot_send_event_line() {
    let line = event_to_line(&send_event());
    insta::assert_json_snapshot!("send_event_line", line);
}

#[test]
fn snapshot_recv_event_line() {
    let line = event_to_line(&recv_event());
    insta::assert_json_snapshot!("recv_event_line", line);
}

#[test]
fn snapshot_output_line_event() {
    let line = event_to_line(&connect_event());
    insta::assert_json_snapshot!("output_line_event", line);
}

#[test]
fn snapshot_summary_line() {
    let summary = SummaryLine {
        kind: "summary".into(),
        pid: 1234,
        duration_ms: 5000,
        connections_total: 42,
        bytes_out_total: 102_400,
        bytes_in_total: 204_800,
        pcap_written: true,
    };
    let output = OutputLine::Summary(summary);
    insta::assert_json_snapshot!("output_line_summary", output);
}
