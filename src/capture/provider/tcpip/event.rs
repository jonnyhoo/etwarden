//! # `capture::provider::tcpip::event`
//!
//! **Purpose**: Parses Kernel-Network TCP/IP ferrisetw records into `NetEvent` values.
//! **Public API**: module-private event parser
//! **Dependencies**: `ferrisetw`, `parser::tcpip`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 225 / 280

use chrono::{DateTime, Utc};
use ferrisetw::{parser::Parser, EventRecord, SchemaLocator};

use crate::{
    capture::provider::common::record_timestamp,
    parser::{
        tcpip::{
            EVENT_ID_TCP_CONNECT_IPV4, EVENT_ID_TCP_CONNECT_IPV6, EVENT_ID_TCP_DISCONNECT_IPV4,
            EVENT_ID_TCP_DISCONNECT_IPV6, EVENT_ID_TCP_RECV_IPV4, EVENT_ID_TCP_RECV_IPV6,
            EVENT_ID_TCP_RETRANSMIT_IPV4, EVENT_ID_TCP_RETRANSMIT_IPV6, EVENT_ID_TCP_SEND_IPV4,
            EVENT_ID_TCP_SEND_IPV6, EVENT_ID_UDP_RECV_IPV4, EVENT_ID_UDP_RECV_IPV6,
            EVENT_ID_UDP_SEND_IPV4, EVENT_ID_UDP_SEND_IPV6,
        },
        types::{NetEvent, Protocol},
    },
};

pub(super) fn parse_tcpip_event(record: &EventRecord, locator: &SchemaLocator) -> Option<NetEvent> {
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

fn parse_connect_v4(parser: &Parser<'_, '_>, pid: u32, ts: DateTime<Utc>) -> Option<NetEvent> {
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

fn parse_connect_v6(parser: &Parser<'_, '_>, pid: u32, ts: DateTime<Utc>) -> Option<NetEvent> {
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

fn parse_disconnect_v4(parser: &Parser<'_, '_>, pid: u32, ts: DateTime<Utc>) -> Option<NetEvent> {
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

fn parse_disconnect_v6(parser: &Parser<'_, '_>, pid: u32, ts: DateTime<Utc>) -> Option<NetEvent> {
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

fn parse_send_v4(parser: &Parser<'_, '_>, pid: u32, ts: DateTime<Utc>) -> Option<NetEvent> {
    parse_send_recv_v4(parser, pid, ts, Protocol::Tcp, Direction::Send)
}

fn parse_send_v6(parser: &Parser<'_, '_>, pid: u32, ts: DateTime<Utc>) -> Option<NetEvent> {
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
    ts: DateTime<Utc>,
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
    ts: DateTime<Utc>,
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
    ts: DateTime<Utc>,
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
}
