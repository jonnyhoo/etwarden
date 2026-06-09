use super::test_timestamp;
use crate::{
    output::schema::{convert::*, OutputLine},
    parser::types::{NetEvent, Protocol, RawFrame},
};

#[test]
fn raw_capture_converts_to_error_line() {
    let event = NetEvent::RawCapture {
        frame: RawFrame {
            timestamp: test_timestamp(),
            data: vec![0xde, 0xad, 0xbe, 0xef],
        },
        pid: 1234,
    };
    let line = event_to_line(&event);
    let OutputLine::Error(line) = line else {
        unreachable!()
    };
    assert_eq!(line.kind, "error");
    assert_eq!(
        line.message,
        "raw capture event cannot be serialized to NDJSON"
    );
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
    let OutputLine::Event(line) = line else {
        unreachable!()
    };
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
    let OutputLine::Event(line) = line else {
        unreachable!()
    };
    assert_eq!(line.event, "disconnect");
    assert_eq!(line.bytes_out, 512);
}

#[test]
fn enriched_line_includes_scope() {
    let event = NetEvent::Connect {
        timestamp: test_timestamp(),
        pid: 1234,
        proto: Protocol::Tcp,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:443".into(),
        bytes_out: 0,
        bytes_in: 0,
    };
    let line = event_to_line_enriched(&event, Some("chrome.exe".into()), None);
    let OutputLine::Event(line) = line else {
        unreachable!()
    };
    assert_eq!(line.scope, Some("PUBLIC".into()));
    assert_eq!(line.process_name, Some("chrome.exe".into()));
}

#[test]
fn recv_scope_uses_remote_destination() {
    let event = NetEvent::Recv {
        timestamp: test_timestamp(),
        pid: 1234,
        proto: Protocol::Udp,
        src: "10.0.0.2:54321".into(),
        dst: "8.8.8.8:53".into(),
        bytes_out: 0,
        bytes_in: 128,
    };
    let line = event_to_line(&event);
    let OutputLine::Event(line) = line else {
        unreachable!()
    };
    assert_eq!(line.scope, Some("PUBLIC".into()));
}
