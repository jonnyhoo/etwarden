//! # `capture::event_loop::tests`
//!
//! **Purpose**: Unit tests for event-loop drain filtering and counters.
//! **Public API**: test module only
//! **Dependencies**: `capture::event_loop`, `filter`, `parser`, `pcap`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 166 / 220

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use super::*;
use crate::{
    error::EtwardenError,
    filter::pid::PidFilter,
    parser::types::{NetEvent, Protocol, RawFrame},
};

#[derive(Default)]
struct CountingEmitter {
    emitted: usize,
}

impl Emitter for CountingEmitter {
    fn emit(&mut self, _event: &NetEvent) -> std::result::Result<(), EtwardenError> {
        self.emitted += 1;
        Ok(())
    }

    fn flush(&mut self) -> std::result::Result<(), EtwardenError> {
        Ok(())
    }
}

struct RecordingPcapSink {
    written_pids: Arc<Mutex<Vec<u32>>>,
}

impl PcapSink for RecordingPcapSink {
    fn write_frame(
        &mut self,
        _frame: &RawFrame,
        pid: u32,
    ) -> std::result::Result<(), EtwardenError> {
        self.written_pids.lock().expect("written pids").push(pid);
        Ok(())
    }
}

fn ts() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .map(|dt| dt.with_timezone(&Utc))
        .expect("valid timestamp")
}

fn raw_capture(pid: u32) -> NetEvent {
    NetEvent::RawCapture {
        frame: RawFrame {
            timestamp: ts(),
            data: vec![0xFF; 14],
        },
        pid,
    }
}

fn connect(pid: u32) -> NetEvent {
    NetEvent::Connect {
        timestamp: ts(),
        pid,
        proto: Protocol::Tcp,
        src: "10.0.0.1:1234".into(),
        dst: "10.0.0.2:443".into(),
        bytes_out: 0,
        bytes_in: 0,
    }
}

fn send(pid: u32, bytes_out: u64) -> NetEvent {
    NetEvent::Send {
        timestamp: ts(),
        pid,
        proto: Protocol::Tcp,
        src: "10.0.0.1:1234".into(),
        dst: "10.0.0.2:443".into(),
        bytes_out,
        bytes_in: 0,
    }
}

fn push_event(registry: &ParserRegistry, event: NetEvent) {
    registry
        .events_buffer()
        .lock()
        .expect("events buffer")
        .push(event);
}

#[test]
fn raw_capture_respects_pid_filter_before_pcap_write() {
    let registry = ParserRegistry::new();
    push_event(&registry, raw_capture(42));
    push_event(&registry, raw_capture(99));
    let filters: Vec<Box<dyn Filter>> = vec![Box::new(PidFilter::single(42))];
    let mut emitter = CountingEmitter::default();
    let written_pids = Arc::new(Mutex::new(Vec::new()));
    let mut sink: Box<dyn PcapSink> = Box::new(RecordingPcapSink {
        written_pids: Arc::clone(&written_pids),
    });
    let mut pcap_sink = Some(&mut sink);

    let stats = drain_events(&registry, &filters, &mut emitter, &mut pcap_sink, None)
        .expect("drain events");

    assert!(stats.pcap_written);
    assert_eq!(emitter.emitted, 0);
    assert_eq!(*written_pids.lock().expect("written pids"), vec![42]);
}

#[test]
fn filtered_raw_capture_does_not_mark_pcap_written() {
    let registry = ParserRegistry::new();
    push_event(&registry, raw_capture(99));
    let filters: Vec<Box<dyn Filter>> = vec![Box::new(PidFilter::single(42))];
    let mut emitter = CountingEmitter::default();
    let written_pids = Arc::new(Mutex::new(Vec::new()));
    let mut sink: Box<dyn PcapSink> = Box::new(RecordingPcapSink {
        written_pids: Arc::clone(&written_pids),
    });
    let mut pcap_sink = Some(&mut sink);

    let stats = drain_events(&registry, &filters, &mut emitter, &mut pcap_sink, None)
        .expect("drain events");

    assert!(!stats.pcap_written);
    assert_eq!(emitter.emitted, 0);
    assert!(written_pids.lock().expect("written pids").is_empty());
}

#[test]
fn non_raw_events_still_emit_after_filter() {
    let registry = ParserRegistry::new();
    push_event(&registry, connect(42));
    push_event(&registry, connect(99));
    let filters: Vec<Box<dyn Filter>> = vec![Box::new(PidFilter::single(42))];
    let mut emitter = CountingEmitter::default();
    let mut pcap_sink = None;

    let stats = drain_events(&registry, &filters, &mut emitter, &mut pcap_sink, None)
        .expect("drain events");

    assert!(!stats.pcap_written);
    assert_eq!(emitter.emitted, 1);
    assert_eq!(stats.connections_total, 1);
}

#[test]
fn summary_byte_totals_saturate() {
    let registry = ParserRegistry::new();
    push_event(&registry, send(42, u64::MAX));
    push_event(&registry, send(42, 1));
    let filters: Vec<Box<dyn Filter>> = vec![Box::new(PidFilter::single(42))];
    let mut emitter = CountingEmitter::default();
    let mut pcap_sink = None;

    let stats = drain_events(&registry, &filters, &mut emitter, &mut pcap_sink, None)
        .expect("drain events");

    assert_eq!(emitter.emitted, 2);
    assert_eq!(stats.bytes_out_total, u64::MAX);
}
