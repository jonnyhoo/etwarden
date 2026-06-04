//! # `capture::provider`
//!
//! **Purpose**: Builds pre-configured ferrisetw Provider instances.
//! **Public API**: `fn build_tcpip_provider()`, `fn build_ndis_provider()`
//! **Dependencies**: `ferrisetw`, `capture::timestamp`, `parser::*`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 392 / 500

use std::sync::Arc;

use ferrisetw::{parser::Parser, provider::Provider, EventRecord, SchemaLocator};

use crate::{
    capture::timestamp,
    parser::{
        ndis::{normalize_frame, NdisParser, PROVIDER_NDIS},
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

const NDIS_PACKET_FRAGMENT_EVENT_IDS: [u16; 2] = [1001, 1003];
const NDIS_PACKET_KEYWORDS: u64 = u64::MAX;

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
                registry.push_event(event);
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
    let dport = parse_network_port(parser, "dport")?;
    let sport = parse_network_port(parser, "sport")?;
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
    let dport = parse_network_port(parser, "dport")?;
    let sport = parse_network_port(parser, "sport")?;
    Some(NetEvent::Connect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format_ip_addr_port(&saddr, sport),
        dst: format_ip_addr_port(&daddr, dport),
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
    let dport = parse_network_port(parser, "dport")?;
    let sport = parse_network_port(parser, "sport")?;
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
    let dport = parse_network_port(parser, "dport")?;
    let sport = parse_network_port(parser, "sport")?;
    Some(NetEvent::Disconnect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format_ip_addr_port(&saddr, sport),
        dst: format_ip_addr_port(&daddr, dport),
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
    let dport = parse_network_port(parser, "dport")?;
    let sport = parse_network_port(parser, "sport")?;
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
    let dport = parse_network_port(parser, "dport")?;
    let sport = parse_network_port(parser, "sport")?;
    Some(make_send_recv_event(
        ts,
        pid,
        proto,
        format_ip_addr_port(&saddr, sport),
        format_ip_addr_port(&daddr, dport),
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

fn format_ip_addr_port(ip: &std::net::IpAddr, port: u16) -> String {
    match ip {
        std::net::IpAddr::V4(addr) => format!("{addr}:{port}"),
        std::net::IpAddr::V6(addr) => format!("[{addr}]:{port}"),
    }
}

fn parse_network_port(parser: &Parser<'_, '_>, name: &str) -> Option<u16> {
    parser.try_parse::<u16>(name).ok().map(network_port)
}

const fn network_port(raw: u16) -> u16 {
    u16::from_be(raw)
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
        .any(NDIS_PACKET_KEYWORDS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let Some(timestamp) = record_timestamp(record) else {
                return;
            };

            if !is_ndis_packet_fragment_event(record.event_id()) {
                return;
            }

            let Some(data) = parse_ndis_frame_buffer(record, locator) else {
                eprintln!("[etwarden] dropped NDIS packet: missing or empty packet fragment");
                return;
            };
            let Some(data) = normalize_frame(data) else {
                return;
            };

            let raw = RawEvent {
                event_id: record.event_id(),
                pid: record.process_id(),
                timestamp,
                data,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ip_addr_port_keeps_ipv4_plain() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(format_ip_addr_port(&ip, 443), "127.0.0.1:443");
    }

    #[test]
    fn format_ip_addr_port_brackets_ipv6() {
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(format_ip_addr_port(&ip, 443), "[::1]:443");
    }

    #[test]
    fn network_port_decodes_wire_order() {
        let raw = u16::from_ne_bytes(443u16.to_be_bytes());
        assert_eq!(network_port(raw), 443);
    }

    #[test]
    fn ndis_packet_fragment_events_include_vmswitch_packet() {
        assert!(is_ndis_packet_fragment_event(1001));
        assert!(is_ndis_packet_fragment_event(1003));
        assert!(!is_ndis_packet_fragment_event(1002));
    }
}
