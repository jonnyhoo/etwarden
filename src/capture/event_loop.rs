//! # `capture::event_loop`
//!
//! **Purpose**: Main ETW event processing loop — drain, filter, emit.
//! **Public API**: `fn run_event_loop()`
//! **Dependencies**: `capture::session`, `parser`, `filter`, `output`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 240 / 260

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use crate::{
    capture::session::RunningSession,
    error::Result,
    filter::Filter,
    output::{schema::SummaryLine, Emitter},
    parser::{types::NetEvent, ParserRegistry},
    pcap::{correlator::Correlator, PcapSink},
};

// ---------------------------------------------------------------------------
// run_event_loop
// ---------------------------------------------------------------------------

/// Runs the main event processing loop.
///
/// Drains events from the `ParserRegistry`, applies filters, and emits
/// matching events via the `Emitter`. Blocks until the session is stopped
/// (typically from another thread or Ctrl+C handler).
///
/// # Arguments
/// * `session` — The running ETW trace session.
/// * `registry` — Shared parser registry with buffered events.
/// * `filters` — Filters to apply; events must pass ALL filters.
/// * `emitter` — Output emitter for NDJSON lines.
///
/// # Returns
/// A `SummaryLine` with aggregate statistics.
///
/// # Errors
/// Returns [`EtwardenError`] on emission or session errors.
pub fn run_event_loop(
    mut session: RunningSession,
    registry: &ParserRegistry,
    filters: &[Box<dyn Filter>],
    emitter: &mut dyn Emitter,
    mut pcap_sink: Option<&mut Box<dyn PcapSink>>,
    correlator: Option<&Correlator>,
    duration: Option<Duration>,
    stop_signal: Option<&AtomicBool>,
) -> Result<SummaryLine> {
    let mut connections_total: u64 = 0;
    let mut bytes_out_total: u64 = 0;
    let mut bytes_in_total: u64 = 0;
    let mut pcap_written = false;
    let started = Instant::now();

    loop {
        let stats = drain_events(registry, filters, emitter, &mut pcap_sink, correlator)?;
        connections_total = connections_total.saturating_add(stats.connections_total);
        bytes_out_total = bytes_out_total.saturating_add(stats.bytes_out_total);
        bytes_in_total = bytes_in_total.saturating_add(stats.bytes_in_total);
        pcap_written |= stats.pcap_written;

        if should_stop(started, duration, stop_signal) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let stop_result = session.stop();

    let stats = drain_events(registry, filters, emitter, &mut pcap_sink, correlator)?;
    connections_total = connections_total.saturating_add(stats.connections_total);
    bytes_out_total = bytes_out_total.saturating_add(stats.bytes_out_total);
    bytes_in_total = bytes_in_total.saturating_add(stats.bytes_in_total);
    pcap_written |= stats.pcap_written;
    emitter.flush()?;
    stop_result?;

    Ok(SummaryLine {
        kind: "summary".into(),
        pid: 0, // Filled by caller.
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        connections_total,
        bytes_out_total,
        bytes_in_total,
        pcap_written,
    })
}

struct LoopStats {
    connections_total: u64,
    bytes_out_total: u64,
    bytes_in_total: u64,
    pcap_written: bool,
}

fn drain_events(
    registry: &ParserRegistry,
    filters: &[Box<dyn Filter>],
    emitter: &mut dyn Emitter,
    pcap_sink: &mut Option<&mut Box<dyn PcapSink>>,
    correlator: Option<&Correlator>,
) -> Result<LoopStats> {
    let mut stats = LoopStats {
        connections_total: 0,
        bytes_out_total: 0,
        bytes_in_total: 0,
        pcap_written: false,
    };
    let events = registry.drain();
    for event in &events {
        // Apply all filters before any output. RawCapture must not bypass the target PID filter.
        let passes = filters.iter().all(|f| f.allow(event));
        if !passes {
            continue;
        }

        // Route RawCapture to pcap sink, not emitter.
        if let NetEvent::RawCapture { frame, pid } = event {
            if let Some(sink) = pcap_sink.as_mut() {
                sink.write_frame(frame, *pid)?;
                stats.pcap_written = true;
            }
            continue;
        }

        if let Some(corr) = correlator {
            corr.register_event(event);
        }

        emitter.emit(event)?;
        if matches!(event, NetEvent::Connect { .. }) {
            stats.connections_total = stats.connections_total.saturating_add(1);
        }
        stats.bytes_out_total = stats.bytes_out_total.saturating_add(event.bytes_out());
        stats.bytes_in_total = stats.bytes_in_total.saturating_add(event.bytes_in());
    }
    Ok(stats)
}

fn should_stop(
    started: Instant,
    duration: Option<Duration>,
    stop_signal: Option<&AtomicBool>,
) -> bool {
    duration.is_some_and(|limit| started.elapsed() >= limit)
        || stop_signal.is_some_and(|signal| signal.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::{
        error::EtwardenError,
        filter::pid::PidFilter,
        parser::types::{Protocol, RawFrame},
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
}
