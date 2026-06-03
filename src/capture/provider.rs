//! # `capture::provider`
//!
//! **Purpose**: Builds pre-configured ferrisetw Provider instances.
//! **Public API**: `fn build_tcpip_provider()`, `fn build_ndis_provider()`,
//!                `fn build_correlation_provider()`, `fn build_dns_client_provider()`
//! **Dependencies**: `ferrisetw`, `parser::*`, `parser::dns_codes`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 380 / 450

use ferrisetw::{parser::Parser, provider::Provider, EventRecord, SchemaLocator};

use crate::parser::{
    correlation::{ActivityMap, PROVIDER_CORRELATION},
    dns_codes::{dns_status_name, dns_type_name, parse_query_results},
    ndis::PROVIDER_NDIS,
    tcpip::{
        EVENT_ID_TCP_CONNECT_IPV4, EVENT_ID_TCP_CONNECT_IPV6, EVENT_ID_TCP_DISCONNECT_IPV4,
        EVENT_ID_TCP_DISCONNECT_IPV6, EVENT_ID_TCP_RECV_IPV4, EVENT_ID_TCP_RECV_IPV6,
        EVENT_ID_TCP_SEND_IPV4, EVENT_ID_TCP_SEND_IPV6, PROVIDER_TCPIP,
    },
    types::{NetEvent, Protocol, RawFrame},
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
        bytes_out: 0,
        bytes_in: u64::from(size),
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
        bytes_out: 0,
        bytes_in: u64::from(size),
    })
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

/// Builds the Microsoft-Windows-NDIS-PacketCapture ETW provider with a
/// callback that wraps raw frame data into `NetEvent::RawCapture` and
/// pushes it to the given `ParserRegistry`.
pub fn build_ndis_provider(registry: std::sync::Arc<ParserRegistry>) -> Provider {
    Provider::by_guid(PROVIDER_NDIS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let pid = record.process_id();
            let timestamp = chrono::Utc::now();

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

            let frame = RawFrame { timestamp, data };
            if let Ok(mut events) = registry.events_buffer().lock() {
                events.push(NetEvent::RawCapture { frame, pid });
            }
        })
        .build()
}

// ---------------------------------------------------------------------------
// build_correlation_provider
// ---------------------------------------------------------------------------

/// Builds the Microsoft-Windows-Networking-Correlation ETW provider with a
/// callback that populates the given `ActivityMap`.
pub fn build_correlation_provider(activity_map: std::sync::Arc<ActivityMap>) -> Provider {
    Provider::by_guid(PROVIDER_CORRELATION)
        .add_callback(move |record: &EventRecord, _locator: &SchemaLocator| {
            // Correlation event parsing will be implemented when the schema
            // is reverse-engineered. For now, we just acknowledge the callback.
            let _ = (record, &activity_map);
        })
        .build()
}

// ---------------------------------------------------------------------------
// build_dns_client_provider
// ---------------------------------------------------------------------------

/// Microsoft-Windows-DNS-Client ETW provider GUID.
const PROVIDER_DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// `EventID` 3006 — DNS query issued by the local resolver.
const EVENT_ID_DNS_QUERY: u16 = 3006;

/// `EventID` 3008 — DNS response received by the local resolver.
const EVENT_ID_DNS_RESPONSE: u16 = 3008;

/// Builds the Microsoft-Windows-DNS-Client ETW provider with a callback that
/// parses DNS query (3006) and response (3008) events.
///
/// This provider works with encrypted DNS (DoH/DoT) because the OS resolver
/// has already parsed the DNS payload before emitting the ETW event.
pub fn build_dns_client_provider(registry: std::sync::Arc<ParserRegistry>) -> Provider {
    Provider::by_guid(PROVIDER_DNS_CLIENT)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(event) = parse_dns_client_event(record, locator) {
                if let Ok(mut events) = registry.events_buffer().lock() {
                    events.push(event);
                }
            }
        })
        .build()
}

/// Dispatches DNS Client ETW events by `EventID`.
fn parse_dns_client_event(record: &EventRecord, locator: &SchemaLocator) -> Option<NetEvent> {
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let event_id = record.event_id();
    let pid = record.process_id();
    let timestamp = chrono::Utc::now();

    match event_id {
        EVENT_ID_DNS_QUERY => parse_dns_query(&parser, pid, timestamp),
        EVENT_ID_DNS_RESPONSE => parse_dns_response(&parser, pid, timestamp),
        _ => None,
    }
}

/// Parses `EventID` 3006 (DNS query) fields.
///
/// `WhoYouCalling` extracts: `QueryName`, `QueryType`, `QueryOptions`.
/// We extract the same plus resolve the human-readable type name.
fn parse_dns_query(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let domain: String = parser.try_parse("QueryName").ok()?;
    let query_type: u16 = parser.try_parse("QueryType").ok()?;

    Some(NetEvent::DnsQuery {
        timestamp: ts,
        pid,
        domain,
        query_type,
        query_type_name: dns_type_name(query_type).to_string(),
    })
}

/// Parses `EventID` 3008 (DNS response) fields.
///
/// `WhoYouCalling` extracts: `QueryName`, `QueryType`, `QueryResults`, `QueryStatus`.
/// We extract the same plus parse resolved IPs from `QueryResults` and
/// resolve human-readable type/status names.
fn parse_dns_response(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<NetEvent> {
    let domain: String = parser.try_parse("QueryName").ok()?;
    let query_type: u16 = parser.try_parse("QueryType").ok()?;
    let status: u32 = parser.try_parse("QueryStatus").ok()?;

    // QueryResults format: "1.2.3.4;5.6.7.8;type: 1 example.com;"
    let query_results: String = parser.try_parse("QueryResults").unwrap_or_default();
    let result_ips = parse_query_results(&query_results);

    Some(NetEvent::DnsResponse {
        timestamp: ts,
        pid,
        domain,
        query_type,
        query_type_name: dns_type_name(query_type).to_string(),
        status,
        status_name: dns_status_name(status).to_string(),
        result_ips,
    })
}
