//! # `capture::provider`
//!
//! **Purpose**: Builds pre-configured ferrisetw Provider instances.
//! **Public API**: `fn build_tcpip_provider()`, `fn build_ndis_provider()`
//! **Dependencies**: `ferrisetw`, `capture::timestamp`, `parser::*`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 356 / 500

use std::sync::Arc;

use ferrisetw::{parser::Parser, provider::Provider, EventRecord, SchemaLocator};

use crate::{
    capture::timestamp,
    parser::{
        ndis::{NdisParser, PROVIDER_NDIS},
        tcpip::{
            EVENT_ID_TCP_CONNECT_IPV4, EVENT_ID_TCP_CONNECT_IPV6, EVENT_ID_TCP_DISCONNECT_IPV4,
            EVENT_ID_TCP_DISCONNECT_IPV6, EVENT_ID_TCP_RECV_IPV4, EVENT_ID_TCP_RECV_IPV6,
            EVENT_ID_TCP_RETRANSMIT_IPV4, EVENT_ID_TCP_RETRANSMIT_IPV6, EVENT_ID_TCP_SEND_IPV4,
            EVENT_ID_TCP_SEND_IPV6, EVENT_ID_UDP_RECV_IPV4, EVENT_ID_UDP_RECV_IPV6,
            EVENT_ID_UDP_SEND_IPV4, EVENT_ID_UDP_SEND_IPV6, PROVIDER_TCPIP,
        },
        types::{NetEvent, Protocol, RawEvent},
        EventParser, ParserRegistry,
    },
    pcap::correlator::Correlator,
};

// ---------------------------------------------------------------------------
// build_tcpip_provider
// ---------------------------------------------------------------------------

/// Builds the Microsoft-Windows-Kernel-Network ETW provider.
///
/// Parses events using ferrisetw's `Parser` and dispatches `NetEvent`s
/// to the given `ParserRegistry`.
pub fn build_tcpip_provider(
    registry: Arc<ParserRegistry>,
    correlator: Option<Arc<Correlator>>,
) -> Provider {
    Provider::by_guid(PROVIDER_TCPIP)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(event) = parse_tcpip_event(record, locator) {
                if let Some(corr) = correlator.as_deref() {
                    corr.register_event(&event);
                }
                if let Ok(mut events) = registry.events_buffer().lock() {
                    events.push(event);
                }
            }
        })
        .build()
}

// ---------------------------------------------------------------------------
// Parsing helpers (using ferrisetw Parser)
// ---------------------------------------------------------------------------

/// Parses a Kernel-Network TCP ETW event record.
///
/// Uses ferrisetw's schema parser so the event PID comes from the manifest
/// `PID` field rather than the ETW header process ID.
fn parse_tcpip_event(record: &EventRecord, locator: &SchemaLocator) -> Option<NetEvent> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let event_id = record.event_id();
    let pid = parse_kernel_network_pid(&parser)?;
    let timestamp = record_timestamp(record)?;

    match event_id {
        EVENT_ID_TCP_CONNECT_IPV4 => parse_connect_v4(&parser, pid, timestamp),
        EVENT_ID_TCP_CONNECT_IPV6 => parse_connect_v6(&parser, pid, timestamp),
        EVENT_ID_TCP_DISCONNECT_IPV4 => parse_disconnect_v4(&parser, pid, timestamp),
        EVENT_ID_TCP_DISCONNECT_IPV6 => parse_disconnect_v6(&parser, pid, timestamp),
        EVENT_ID_TCP_SEND_IPV4 | EVENT_ID_TCP_RETRANSMIT_IPV4 => {
            parse_send_v4(&parser, pid, timestamp)
        }
        EVENT_ID_TCP_SEND_IPV6 | EVENT_ID_TCP_RETRANSMIT_IPV6 => {
            parse_send_v6(&parser, pid, timestamp)
        }
        EVENT_ID_TCP_RECV_IPV4 => {
            parse_send_recv_v4(&parser, pid, timestamp, Protocol::Tcp, Direction::Recv)
        }
        EVENT_ID_TCP_RECV_IPV6 => {
            parse_send_recv_v6(&parser, pid, timestamp, Protocol::Tcp, Direction::Recv)
        }
        EVENT_ID_UDP_SEND_IPV4 => {
            parse_send_recv_v4(&parser, pid, timestamp, Protocol::Udp, Direction::Send)
        }
        EVENT_ID_UDP_RECV_IPV4 => {
            parse_send_recv_v4(&parser, pid, timestamp, Protocol::Udp, Direction::Recv)
        }
        EVENT_ID_UDP_SEND_IPV6 => {
            parse_send_recv_v6(&parser, pid, timestamp, Protocol::Udp, Direction::Send)
        }
        EVENT_ID_UDP_RECV_IPV6 => {
            parse_send_recv_v6(&parser, pid, timestamp, Protocol::Udp, Direction::Recv)
        }
        _ => None,
    }
}

fn parse_kernel_network_pid(parser: &Parser<'_, '_>) -> Option<u32> {
    parser.try_parse("PID").ok()
}

fn record_timestamp(record: &EventRecord) -> Option<chrono::DateTime<chrono::Utc>> {
    timestamp::from_filetime_100ns(record.raw_timestamp())
}

fn parse_connect_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let daddr: u32 = parser.try_parse("daddr").ok()?;
    let saddr: u32 = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Connect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format_addr_port(saddr, sport),
        dst: format_addr_port(daddr, dport),
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_connect_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let daddr: std::net::IpAddr = parser.try_parse("daddr").ok()?;
    let saddr: std::net::IpAddr = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Connect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format!("{saddr}:{sport}"),
        dst: format!("{daddr}:{dport}"),
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_disconnect_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let daddr: u32 = parser.try_parse("daddr").ok()?;
    let saddr: u32 = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Disconnect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format_addr_port(saddr, sport),
        dst: format_addr_port(daddr, dport),
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_disconnect_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let daddr: std::net::IpAddr = parser.try_parse("daddr").ok()?;
    let saddr: std::net::IpAddr = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Disconnect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format!("{saddr}:{sport}"),
        dst: format!("{daddr}:{dport}"),
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_send_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    parse_send_recv_v4(parser, pid, ts, Protocol::Tcp, Direction::Send)
}

fn parse_send_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    parse_send_recv_v6(parser, pid, ts, Protocol::Tcp, Direction::Send)
}

#[derive(Clone, Copy)]
enum Direction {
    Send,
    Recv,
}

fn parse_send_recv_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
    proto: Protocol,
    direction: Direction,
) -> Option<NetEvent> {
    let size: u32 = parser.try_parse("size").ok()?;
    let daddr: u32 = parser.try_parse("daddr").ok()?;
    let saddr: u32 = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(make_send_recv_event(
        ts,
        pid,
        proto,
        format_addr_port(saddr, sport),
        format_addr_port(daddr, dport),
        size,
        direction,
    ))
}

fn parse_send_recv_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
    proto: Protocol,
    direction: Direction,
) -> Option<NetEvent> {
    let size: u32 = parser.try_parse("size").ok()?;
    let daddr: std::net::IpAddr = parser.try_parse("daddr").ok()?;
    let saddr: std::net::IpAddr = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(make_send_recv_event(
        ts,
        pid,
        proto,
        format!("{saddr}:{sport}"),
        format!("{daddr}:{dport}"),
        size,
        direction,
    ))
}

fn make_send_recv_event(
    ts: chrono::DateTime<chrono::Utc>,
    pid: u32,
    proto: Protocol,
    src: String,
    dst: String,
    size: u32,
    direction: Direction,
) -> NetEvent {
    match direction {
        Direction::Send => NetEvent::Send {
            timestamp: ts,
            pid,
            proto,
            src,
            dst,
            bytes_out: u64::from(size),
            bytes_in: 0,
        },
        Direction::Recv => NetEvent::Recv {
            timestamp: ts,
            pid,
            proto,
            src,
            dst,
            bytes_out: 0,
            bytes_in: u64::from(size),
        },
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_addr_port(raw_ip: u32, port: u16) -> String {
    let ip = std::net::Ipv4Addr::from(raw_ip.to_be());
    format!("{ip}:{port}")
}

// ---------------------------------------------------------------------------
// build_ndis_provider
// ---------------------------------------------------------------------------

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
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let Some(timestamp) = record_timestamp(record) else {
                return;
            };

            // Extract raw frame bytes via ferrisetw's Parser.
            // NDIS PacketCapture events typically have a "FrameBuffer" property.
            // If schema parsing fails, fall back to empty data.
            let data = locator
                .event_schema(record)
                .ok()
                .and_then(|schema| {
                    let parser = Parser::create(record, &schema);
                    parser.try_parse::<Vec<u8>>("FrameBuffer").ok()
                })
                .unwrap_or_default();

            let raw = RawEvent {
                event_id: record.event_id(),
                pid: record.process_id(),
                timestamp,
                data,
            };
            if let Some(event) = parser.parse_dns_event(&raw) {
                if let Ok(mut events) = registry.events_buffer().lock() {
                    events.push(event);
                }
            }
            if emit_raw_capture {
                if let Some(event) = parser.parse(&raw) {
                    if let Ok(mut events) = registry.events_buffer().lock() {
                        events.push(event);
                    }
                }
            }
        })
        .build()
}
