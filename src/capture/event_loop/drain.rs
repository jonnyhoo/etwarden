//! # `capture::event_loop::drain`
//!
//! **Purpose**: Drains buffered parser events through filters, pcap sink, correlator, and emitter.
//! **Public API**: module-private drain loop and stats
//! **Dependencies**: `filter`, `output`, `parser`, `pcap`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 80 / 120

use crate::{
    error::Result,
    filter::Filter,
    output::Emitter,
    parser::{types::NetEvent, ParserRegistry},
    pcap::{correlator::Correlator, PcapSink},
};

#[derive(Clone, Copy, Default)]
pub(super) struct LoopStats {
    pub(super) connections_total: u64,
    pub(super) bytes_out_total: u64,
    pub(super) bytes_in_total: u64,
    pub(super) pcap_written: bool,
}

impl LoopStats {
    pub(super) const fn merge(&mut self, other: Self) {
        self.connections_total = self
            .connections_total
            .saturating_add(other.connections_total);
        self.bytes_out_total = self.bytes_out_total.saturating_add(other.bytes_out_total);
        self.bytes_in_total = self.bytes_in_total.saturating_add(other.bytes_in_total);
        self.pcap_written |= other.pcap_written;
    }

    const fn record_emitted(&mut self, event: &NetEvent) {
        if matches!(event, NetEvent::Connect { .. }) {
            self.connections_total = self.connections_total.saturating_add(1);
        }
        self.bytes_out_total = self.bytes_out_total.saturating_add(event.bytes_out());
        self.bytes_in_total = self.bytes_in_total.saturating_add(event.bytes_in());
    }
}

pub(super) fn drain_events(
    registry: &ParserRegistry,
    filters: &[Box<dyn Filter>],
    emitter: &mut dyn Emitter,
    pcap_sink: &mut Option<&mut Box<dyn PcapSink>>,
    correlator: Option<&Correlator>,
) -> Result<LoopStats> {
    let mut stats = LoopStats::default();
    let events = registry.drain();
    for event in &events {
        // Apply all filters before any output. RawCapture must not bypass the target PID filter.
        if !filters.iter().all(|f| f.allow(event)) {
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
        stats.record_emitted(event);
    }
    Ok(stats)
}
