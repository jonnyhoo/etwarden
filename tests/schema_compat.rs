//! # `schema_compat`
//!
//! **Purpose**: Snapshot tests for every `OutputLine` variant via insta.
//!              These snapshots are the schema regression guard.
//! **Public API**: (integration test)
//! **Dependencies**: `etwarden`, `insta`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 224 / 260

use chrono::{TimeZone, Utc};
use etwarden::{
    output::schema::{event_to_line, ErrorLine, OutputLine, SummaryLine},
    parser::types::{NetEvent, Protocol},
};

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
        src: "10.0.0.2:54321".into(),
        dst: "8.8.8.8:53".into(),
        bytes_out: 0,
        bytes_in: 128,
    }
}

fn dns_query_event() -> NetEvent {
    NetEvent::DnsQuery {
        timestamp: ts(),
        pid: 1234,
        domain: "example.com".into(),
        query_type: 1,
        query_type_name: "A".into(),
    }
}

fn dns_response_event() -> NetEvent {
    NetEvent::DnsResponse {
        timestamp: ts(),
        pid: 1234,
        domain: "example.com".into(),
        query_type: 1,
        query_type_name: "A".into(),
        status: 0,
        status_name: "NOERROR".into(),
        result_ips: vec!["93.184.216.34".into()],
        truncated: false,
    }
}

fn http_request_event() -> NetEvent {
    NetEvent::HttpRequest {
        timestamp: ts(),
        pid: 1234,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:80".into(),
        method: "GET".into(),
        path: "/api/data".into(),
        host: Some("example.com".into()),
        version: "HTTP/1.1".into(),
        content_type: Some("application/json".into()),
        content_length: Some(42),
    }
}

fn http_response_event() -> NetEvent {
    NetEvent::HttpResponse {
        timestamp: ts(),
        pid: 1234,
        src: "93.184.216.34:80".into(),
        dst: "10.0.0.1:49152".into(),
        status_line: "HTTP/1.1 200 OK".into(),
        host: None,
        version: "HTTP/1.1".into(),
        status_code: 200,
        content_type: Some("application/json".into()),
        content_length: Some(1234),
    }
}

fn tls_hello_event() -> NetEvent {
    NetEvent::TlsHello {
        timestamp: ts(),
        pid: 1234,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:443".into(),
        sni: Some("example.com".into()),
        version: Some("TLS 1.3".into()),
        ja3: "771,4865,0-16-43,,".into(),
        ja3_hash: "9cd3a3df22ead6ac1977bf836d6ea964".into(),
        ja3n: "771,4865,0-16-43,,".into(),
        ja3n_hash: "9cd3a3df22ead6ac1977bf836d6ea964".into(),
        ja4: "t13d0103h2_0f2cb44170f4_4835ae301cc7".into(),
        ja4o: "t13d0103h2_0f2cb44170f4_4835ae301cc7".into(),
        ja4r: "t13d0103h2_1301_00000010002b_".into(),
        ja4ro: "t13d0103h2_1301_00000010002b_".into(),
        alpn: vec!["h2".into(), "http/1.1".into()],
        cipher_count: 1,
        extension_count: 3,
    }
}

fn tunnel_data_event() -> NetEvent {
    NetEvent::TunnelData {
        timestamp: ts(),
        pid: 1234,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:443".into(),
        direction: "request".into(),
        encrypted: true,
        headers_base64: None,
        headers_truncated: false,
        payload_base64: Some("YWJj".into()),
        payload_truncated: true,
        bytes_seen: 4096,
        bytes_captured: 3,
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
fn snapshot_dns_query_event_line() {
    let line = event_to_line(&dns_query_event());
    insta::assert_json_snapshot!("dns_query_event_line", line);
}

#[test]
fn snapshot_dns_response_event_line() {
    let line = event_to_line(&dns_response_event());
    insta::assert_json_snapshot!("dns_response_event_line", line);
}

#[test]
fn snapshot_http_request_event_line() {
    let line = event_to_line(&http_request_event());
    insta::assert_json_snapshot!("http_request_event_line", line);
}

#[test]
fn snapshot_http_response_event_line() {
    let line = event_to_line(&http_response_event());
    insta::assert_json_snapshot!("http_response_event_line", line);
}

#[test]
fn snapshot_tls_hello_event_line() {
    let line = event_to_line(&tls_hello_event());
    insta::assert_json_snapshot!("tls_hello_event_line", line);
}

#[test]
fn snapshot_tunnel_data_event_line() {
    let line = event_to_line(&tunnel_data_event());
    insta::assert_json_snapshot!("tunnel_data_event_line", line);
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

#[test]
fn snapshot_error_line() {
    let output = OutputLine::Error(ErrorLine::new("capture failed"));
    insta::assert_json_snapshot!("output_line_error", output);
}
