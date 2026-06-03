//! # `capture::provider`
//!
//! **Purpose**: Builds pre-configured ferrisetw Provider instances.
//! **Public API**: `fn build_tcpip_provider()`
//! **Dependencies**: `ferrisetw`, `parser::tcpip`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 140

use ferrisetw::{parser::Parser, provider::Provider, EventRecord, SchemaLocator};

use crate::parser::{
    tcpip::{
        EVENT_ID_TCP_CONNECT_IPV4, EVENT_ID_TCP_CONNECT_IPV6, EVENT_ID_TCP_DISCONNECT_IPV4,
        EVENT_ID_TCP_DISCONNECT_IPV6, EVENT_ID_TCP_RECV_IPV4, EVENT_ID_TCP_RECV_IPV6,
        EVENT_ID_TCP_SEND_IPV4, EVENT_ID_TCP_SEND_IPV6, PROVIDER_TCPIP,
    },
    types::{NetEvent, Protocol},
    ParserRegistry,
};

// ---------------------------------------------------------------------------
// build_tcpip_provider
// ---------------------------------------------------------------------------

/// Builds the Microsoft-Windows-TCPIP ETW provider with a callback that
/// parses events using ferrisetw's `Parser` and dispatches `NetEvent`s
/// to the given `ParserRegistry` (used as a shared event buffer).
pub fn build_tcpip_provider(registry: std::sync::Arc<ParserRegistry>) -> Provider {
    Provider::by_guid(PROVIDER_TCPIP)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(event) = parse_tcpip_event(record, locator) {
                // We reuse dispatch to push into the buffer.
                // The EventParser dispatch expects RawEvent, so we push directly.
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

/// Parses a TCPIP ETW event record into a `NetEvent` using ferrisetw's schema parser.
fn parse_tcpip_event(record: &EventRecord, locator: &SchemaLocator) -> Option<NetEvent> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let event_id = record.event_id();
    let pid = record.process_id();
    let timestamp = chrono::Utc::now();

    match event_id {
        EVENT_ID_TCP_CONNECT_IPV4 => parse_connect_v4(&parser, pid, timestamp),
        EVENT_ID_TCP_CONNECT_IPV6 => parse_connect_v6(&parser, pid, timestamp),
        EVENT_ID_TCP_DISCONNECT_IPV4 => parse_disconnect_v4(&parser, pid, timestamp),
        EVENT_ID_TCP_DISCONNECT_IPV6 => parse_disconnect_v6(&parser, pid, timestamp),
        EVENT_ID_TCP_SEND_IPV4 => parse_send_v4(&parser, pid, timestamp),
        EVENT_ID_TCP_SEND_IPV6 => parse_send_v6(&parser, pid, timestamp),
        EVENT_ID_TCP_RECV_IPV4 => parse_recv_v4(&parser, pid, timestamp),
        EVENT_ID_TCP_RECV_IPV6 => parse_recv_v6(&parser, pid, timestamp),
        _ => None,
    }
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
    let size: u32 = parser.try_parse("size").ok()?;
    let daddr: u32 = parser.try_parse("daddr").ok()?;
    let saddr: u32 = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Send {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format_addr_port(saddr, sport),
        dst: format_addr_port(daddr, dport),
        bytes_out: u64::from(size),
        bytes_in: 0,
    })
}

fn parse_send_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let size: u32 = parser.try_parse("size").ok()?;
    let daddr: std::net::IpAddr = parser.try_parse("daddr").ok()?;
    let saddr: std::net::IpAddr = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Send {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format!("{saddr}:{sport}"),
        dst: format!("{daddr}:{dport}"),
        bytes_out: u64::from(size),
        bytes_in: 0,
    })
}

fn parse_recv_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let size: u32 = parser.try_parse("size").ok()?;
    let daddr: u32 = parser.try_parse("daddr").ok()?;
    let saddr: u32 = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Recv {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format_addr_port(saddr, sport),
        dst: format_addr_port(daddr, dport),
        bytes_out: u64::from(size),
        bytes_in: 0,
    })
}

fn parse_recv_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let size: u32 = parser.try_parse("size").ok()?;
    let daddr: std::net::IpAddr = parser.try_parse("daddr").ok()?;
    let saddr: std::net::IpAddr = parser.try_parse("saddr").ok()?;
    let dport: u16 = parser.try_parse("dport").ok()?;
    let sport: u16 = parser.try_parse("sport").ok()?;
    Some(NetEvent::Recv {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: format!("{saddr}:{sport}"),
        dst: format!("{daddr}:{dport}"),
        bytes_out: u64::from(size),
        bytes_in: 0,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_addr_port(raw_ip: u32, port: u16) -> String {
    let ip = std::net::Ipv4Addr::from(raw_ip.to_be());
    format!("{ip}:{port}")
}
