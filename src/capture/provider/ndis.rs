//! # `capture::provider::ndis`
//!
//! **Purpose**: Builds Microsoft-Windows-NDIS-PacketCapture provider callbacks.
//! **Public API**: `build_ndis_provider`
//! **Dependencies**: `ferrisetw`, `parser::ndis`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 105 / 160

use std::sync::Arc;

use ferrisetw::{parser::Parser, provider::Provider, EventRecord, SchemaLocator};

use crate::{
    capture::provider::common::record_timestamp,
    parser::{
        ndis::{normalize_frame, NdisParser, PROVIDER_NDIS},
        types::RawEvent,
        EventParser, ParserRegistry,
    },
    pcap::correlator::Correlator,
};

const NDIS_PACKET_FRAGMENT_EVENT_IDS: [u16; 2] = [1001, 1003];
const NDIS_PACKET_KEYWORDS: u64 = u64::MAX;

/// Builds the Microsoft-Windows-NDIS-PacketCapture ETW provider.
///
/// The callback emits attributed DNS events from captured UDP/53 frames and
/// optionally emits raw frames for pcap output.
pub fn build_ndis_provider(
    registry: Arc<ParserRegistry>,
    correlator: Arc<Correlator>,
    emit_raw_capture: bool,
) -> Provider {
    let parser = NdisParser::new(correlator);
    Provider::by_guid(PROVIDER_NDIS)
        .any(NDIS_PACKET_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let Some(raw) = parse_raw_ndis_event(record, locator) else {
                return;
            };

            if let Some(event) = parser.parse_dns_event(&raw) {
                registry.push_event(event);
            }
            if emit_raw_capture {
                if let Some(event) = parser.parse(&raw) {
                    registry.push_event(event);
                }
            }
        })
        .build()
}

fn parse_raw_ndis_event(record: &EventRecord, locator: &SchemaLocator) -> Option<RawEvent> {
    if !is_ndis_packet_fragment_event(record.event_id()) {
        return None;
    }

    let timestamp = record_timestamp(record)?;
    let data = parse_ndis_frame(record, locator)?;

    Some(RawEvent {
        event_id: record.event_id(),
        pid: record.process_id(),
        timestamp,
        data,
    })
}

fn parse_ndis_frame(record: &EventRecord, locator: &SchemaLocator) -> Option<Vec<u8>> {
    let data = parse_ndis_frame_buffer(record, locator).or_else(|| {
        eprintln!("[etwarden] dropped NDIS packet: missing or empty packet fragment");
        None
    })?;
    normalize_frame(data)
}

fn parse_ndis_frame_buffer(record: &EventRecord, locator: &SchemaLocator) -> Option<Vec<u8>> {
    if !is_ndis_packet_fragment_event(record.event_id()) {
        return None;
    }

    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let data = parse_packet_bytes(&parser)?;
    (!data.is_empty()).then_some(data)
}

fn parse_packet_bytes(parser: &Parser<'_, '_>) -> Option<Vec<u8>> {
    parser
        .try_parse::<Vec<u8>>("FrameBuffer")
        .or_else(|_| parser.try_parse::<Vec<u8>>("Fragment"))
        .ok()
}

fn is_ndis_packet_fragment_event(event_id: u16) -> bool {
    NDIS_PACKET_FRAGMENT_EVENT_IDS.contains(&event_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndis_packet_fragment_events_include_vmswitch_packet() {
        assert!(is_ndis_packet_fragment_event(1001));
        assert!(is_ndis_packet_fragment_event(1003));
        assert!(!is_ndis_packet_fragment_event(1002));
    }
}
