//! # `parser::ndis`
//!
//! **Purpose**: Parses Microsoft-Windows-NDIS-PacketCapture ETW events into `NetEvent`s.
//! **Public API**: `struct NdisParser` (implements `EventParser`)
//! **Dependencies**: `parser::dns_codes`, `parser::dpi`, `parser::types`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 620 / 680

use std::sync::Arc;

use chrono::{DateTime, Utc};
use windows::core::GUID;

use crate::{
    parser::{
        dns_codes::{dns_status_name, dns_type_name},
        dpi::{self, DpiResult},
        types::{FiveTuple, NetEvent, Protocol, RawEvent, RawFrame},
        EventParser,
    },
    pcap::correlator::Correlator,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Microsoft-Windows-NDIS-PacketCapture provider GUID.
pub const PROVIDER_NDIS: &str = "2ED6006E-4729-4609-B423-3EE7BCD678EF";

// ---------------------------------------------------------------------------
// NdisParser
// ---------------------------------------------------------------------------

/// Parses ETW events from the Microsoft-Windows-NDIS-PacketCapture provider.
///
/// Each event contains a raw Ethernet frame. The parser emits `RawCapture`
/// only when the frame has a TCP/UDP five-tuple that resolves through the
/// shared `Correlator`.
pub struct NdisParser {
    correlator: Arc<Correlator>,
}

impl NdisParser {
    /// Creates a new `NdisParser` with the given correlator for PID resolution.
    #[must_use]
    pub const fn new(correlator: Arc<Correlator>) -> Self {
        Self { correlator }
    }

    /// Parses an attributed DNS event from the raw frame payload.
    #[must_use]
    pub fn parse_dns_event(&self, raw: &RawEvent) -> Option<NetEvent> {
        parse_dns_event(&raw.data, raw.timestamp, &self.correlator)
    }
}

/// Parsed packet metadata extracted from an Ethernet frame.
pub(crate) struct ParsedPacket<'a> {
    pub tuple: FiveTuple,
    pub payload: &'a [u8],
}

/// Builds a per-process DNS event from a captured frame.
pub(crate) fn parse_dns_event(
    frame: &[u8],
    timestamp: DateTime<Utc>,
    correlator: &Correlator,
) -> Option<NetEvent> {
    let packet = extract_packet(frame)?;
    if packet.tuple.protocol != Protocol::Udp {
        return None;
    }

    let pid = correlator.resolve_pid(&packet.tuple)?;
    let DpiResult::Dns(info) =
        dpi::analyze_udp_payload(packet.payload, packet.tuple.src_port, packet.tuple.dst_port)?
    else {
        return None;
    };

    let domain = info.query_name?;
    let query_type = info.query_type?.code();
    let query_type_name = dns_type_name(query_type).to_string();

    if info.is_response {
        let status = info.response_code.unwrap_or(0);
        Some(NetEvent::DnsResponse {
            timestamp,
            pid,
            domain,
            query_type,
            query_type_name,
            status,
            status_name: dns_status_name(status).to_string(),
            result_ips: info
                .response_ips
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
        })
    } else {
        Some(NetEvent::DnsQuery {
            timestamp,
            pid,
            domain,
            query_type,
            query_type_name,
        })
    }
}

impl EventParser for NdisParser {
    fn provider_guid(&self) -> GUID {
        GUID::from(PROVIDER_NDIS)
    }

    fn parse(&self, raw: &RawEvent) -> Option<NetEvent> {
        let packet = extract_packet(&raw.data)?;
        let pid = self.correlator.resolve_pid(&packet.tuple)?;
        let frame = RawFrame {
            timestamp: raw.timestamp,
            data: raw.data.clone(),
        };

        Some(NetEvent::RawCapture { frame, pid })
    }
}

// ---------------------------------------------------------------------------
// Frame header parsing
// ---------------------------------------------------------------------------

/// Ethernet header size in bytes.
const ETH_HDR_LEN: usize = 14;
/// Ethernet type for IPv4.
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
/// Ethernet type for IPv6.
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xDD];
/// IP protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// Extracts a `FiveTuple` and payload slice from raw Ethernet frame bytes.
pub(crate) fn extract_packet(frame: &[u8]) -> Option<ParsedPacket<'_>> {
    if frame.len() < ETH_HDR_LEN + 20 {
        return None;
    }

    let eth_type = &frame[12..14];
    if eth_type == ETHERTYPE_IPV4 {
        parse_ipv4_packet(&frame[ETH_HDR_LEN..])
    } else if eth_type == ETHERTYPE_IPV6 {
        parse_ipv6_packet(&frame[ETH_HDR_LEN..])
    } else {
        None
    }
}

/// Parses IPv4 + TCP/UDP headers to extract packet metadata.
fn parse_ipv4_packet(ip: &[u8]) -> Option<ParsedPacket<'_>> {
    if ip.len() < 20 {
        return None;
    }

    if ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0F) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let fragment_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1FFF;
    if fragment_offset != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if total_len < ihl || total_len > ip.len() {
        return None;
    }
    let protocol = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let transport = ip.get(ihl..total_len)?;
    parse_transport_packet(transport, protocol, src_ip, dst_ip)
}

/// Parses IPv6 + TCP/UDP headers to extract packet metadata.
fn parse_ipv6_packet(ip: &[u8]) -> Option<ParsedPacket<'_>> {
    if ip.len() < 40 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let payload_end = 40usize.checked_add(payload_len)?;
    if payload_end > ip.len() {
        return None;
    }

    let protocol = ip[6];
    let src_ip = format_ipv6(&ip[8..24]);
    let dst_ip = format_ipv6(&ip[24..40]);

    parse_transport_packet(&ip[40..payload_end], protocol, src_ip, dst_ip)
}

/// Parses TCP/UDP transport header for port numbers and payload bytes.
fn parse_transport_packet(
    transport: &[u8],
    protocol: u8,
    src_ip: String,
    dst_ip: String,
) -> Option<ParsedPacket<'_>> {
    if transport.len() < 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

    let (proto, payload) = match protocol {
        IPPROTO_TCP => {
            if transport.len() < 20 {
                return None;
            }
            let data_offset = usize::from(transport[12] >> 4) * 4;
            if data_offset < 20 || transport.len() < data_offset {
                return None;
            }
            (Protocol::Tcp, &transport[data_offset..])
        }
        IPPROTO_UDP => {
            if transport.len() < 8 {
                return None;
            }
            let udp_len = usize::from(u16::from_be_bytes([transport[4], transport[5]]));
            if udp_len < 8 || udp_len > transport.len() {
                return None;
            }
            let payload_end = udp_len;
            (Protocol::Udp, &transport[8..payload_end])
        }
        _ => return None,
    };

    Some(ParsedPacket {
        tuple: FiveTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: proto,
        },
        payload,
    })
}

/// Formats 16 raw bytes as an IPv6 address string (colon-hex).
fn format_ipv6(bytes: &[u8]) -> String {
    use std::net::Ipv6Addr;
    let arr: [u8; 16] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    Ipv6Addr::from(arr).to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};

    use super::*;
    use crate::parser::types::FiveTuple;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
    }

    fn raw_ndis(data: Vec<u8>) -> RawEvent {
        RawEvent {
            event_id: 1,
            pid: 99,
            timestamp: ts(),
            data,
        }
    }

    fn build_ethernet_ipv4_tcp(payload_len: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet header: dst(6) + src(6) + type(2)
        frame.extend_from_slice(&[0xFF; 6]); // dst MAC
        frame.extend_from_slice(&[0xAA; 6]); // src MAC
        frame.extend_from_slice(&ETHERTYPE_IPV4); // IPv4
                                                  // IPv4 header (20 bytes, no options)
        frame.push(0x45); // version=4, ihl=5
        frame.push(0x00); // dscp
        let total_len = u16::try_from(20 + 20 + payload_len).expect("fits in u16");
        frame.extend_from_slice(&total_len.to_be_bytes()); // total length
        frame.extend_from_slice(&[0x00, 0x00]); // identification
        frame.extend_from_slice(&[0x40, 0x00]); // flags + frag (don't fragment)
        frame.push(0x40); // TTL
        frame.push(IPPROTO_TCP); // protocol
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
                                                // src IP: 10.0.0.1
        frame.extend_from_slice(&[10, 0, 0, 1]);
        // dst IP: 10.0.0.2
        frame.extend_from_slice(&[10, 0, 0, 2]);
        // TCP header (20 bytes)
        frame.extend_from_slice(&1234u16.to_be_bytes()); // src port
        frame.extend_from_slice(&80u16.to_be_bytes()); // dst port
        frame.extend_from_slice(&[0u8; 8]); // seq + ack
        frame.push(0x50); // data offset = 5 words, no options
        frame.extend_from_slice(&[0u8; 7]); // flags + window + checksum + urgent
                                            // payload
        frame.extend_from_slice(&vec![0xDD; payload_len]);
        frame
    }

    fn build_ethernet_ipv4_udp(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
        build_ethernet_ipv4_udp_with_ips(payload, [10, 0, 0, 1], [8, 8, 8, 8], src_port, dst_port)
    }

    fn build_ethernet_ipv4_udp_with_ips(
        payload: &[u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xFF; 6]);
        frame.extend_from_slice(&[0xAA; 6]);
        frame.extend_from_slice(&ETHERTYPE_IPV4);
        frame.push(0x45);
        frame.push(0x00);
        let total_len = u16::try_from(20 + 8 + payload.len()).expect("fits in u16");
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x40, 0x00]);
        frame.push(0x40);
        frame.push(IPPROTO_UDP);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = u16::try_from(8 + payload.len()).expect("fits in u16");
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(payload);
        frame
    }

    fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            let bytes = label.as_bytes();
            pkt.push(u8::try_from(bytes.len()).expect("label fits"));
            pkt.extend_from_slice(bytes);
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt
    }

    fn build_dns_response_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut pkt = build_dns_query(name, 1);
        pkt[2] |= 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x01;
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
        pkt.extend_from_slice(&ip);
        pkt
    }

    fn build_ethernet_ipv6_udp(payload_len: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet header
        frame.extend_from_slice(&[0xFF; 6]);
        frame.extend_from_slice(&[0xAA; 6]);
        frame.extend_from_slice(&ETHERTYPE_IPV6);
        // IPv6 header (40 bytes)
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version + flow
        let payload_len_u16 = u16::try_from(8 + payload_len).expect("fits in u16");
        frame.extend_from_slice(&payload_len_u16.to_be_bytes()); // payload length
        frame.push(IPPROTO_UDP); // next header
        frame.push(0x40); // hop limit
                          // src: ::1
        frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst: ::1
        frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // UDP header (8 bytes)
        frame.extend_from_slice(&5678u16.to_be_bytes()); // src port
        frame.extend_from_slice(&443u16.to_be_bytes()); // dst port
        let udp_len = u16::try_from(8 + payload_len).expect("fits in u16");
        frame.extend_from_slice(&udp_len.to_be_bytes()); // length
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
                                                // payload
        frame.extend_from_slice(&vec![0xEE; payload_len]);
        frame
    }

    #[test]
    fn provider_guid_matches() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let expected: GUID = GUID::from(PROVIDER_NDIS);
        assert_eq!(parser.provider_guid(), expected);
    }

    #[test]
    fn parse_ipv4_tcp_frame() {
        let corr = Arc::new(Correlator::new());
        let tuple = FiveTuple {
            src_ip: "10.0.0.1".into(),
            src_port: 1234,
            dst_ip: "10.0.0.2".into(),
            dst_port: 80,
            protocol: Protocol::Tcp,
        };
        corr.register_connection(42, tuple);

        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp(10);
        let raw = raw_ndis(frame.clone());

        let event = parser.parse(&raw).expect("should parse");
        match event {
            NetEvent::RawCapture { frame: f, pid } => {
                assert_eq!(pid, 42);
                assert_eq!(f.data, frame);
                assert_eq!(f.timestamp, ts());
            }
            _ => unreachable!("expected RawCapture"),
        }
    }

    #[test]
    fn parse_ipv6_udp_frame() {
        let corr = Arc::new(Correlator::new());
        let tuple = FiveTuple {
            src_ip: "::1".into(),
            src_port: 5678,
            dst_ip: "::1".into(),
            dst_port: 443,
            protocol: Protocol::Udp,
        };
        corr.register_connection(77, tuple);

        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv6_udp(10);
        let raw = raw_ndis(frame.clone());

        let event = parser.parse(&raw).expect("should parse");
        match event {
            NetEvent::RawCapture { frame: f, pid } => {
                assert_eq!(pid, 77);
                assert_eq!(f.data, frame);
            }
            _ => unreachable!("expected RawCapture"),
        }
    }

    #[test]
    fn parse_dns_query_from_udp_frame() {
        let corr = Arc::new(Correlator::new());
        corr.register_connection(
            42,
            FiveTuple {
                src_ip: "10.0.0.1".into(),
                src_port: 53000,
                dst_ip: "8.8.8.8".into(),
                dst_port: 53,
                protocol: Protocol::Udp,
            },
        );
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_udp(&build_dns_query("example.com", 1), 53000, 53);
        let raw = raw_ndis(frame);

        let event = parser.parse_dns_event(&raw).expect("dns event");
        let NetEvent::DnsQuery {
            pid,
            domain,
            query_type,
            ..
        } = event
        else {
            unreachable!("expected DNS query")
        };
        assert_eq!(pid, 42);
        assert_eq!(domain, "example.com");
        assert_eq!(query_type, 1);
    }

    #[test]
    fn parse_dns_response_from_udp_frame() {
        let corr = Arc::new(Correlator::new());
        corr.register_connection(
            42,
            FiveTuple {
                src_ip: "10.0.0.1".into(),
                src_port: 53000,
                dst_ip: "8.8.8.8".into(),
                dst_port: 53,
                protocol: Protocol::Udp,
            },
        );
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_udp_with_ips(
            &build_dns_response_a("example.com", [93, 184, 216, 34]),
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            53,
            53000,
        );
        let raw = raw_ndis(frame);

        let event = parser.parse_dns_event(&raw).expect("dns event");
        let NetEvent::DnsResponse {
            pid,
            domain,
            status,
            result_ips,
            ..
        } = event
        else {
            unreachable!("expected DNS response")
        };
        assert_eq!(pid, 42);
        assert_eq!(domain, "example.com");
        assert_eq!(status, 0);
        assert_eq!(result_ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn parse_dns_requires_pid_correlation() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_udp(&build_dns_query("example.com", 1), 53000, 53);
        let raw = raw_ndis(frame);
        assert!(parser.parse_dns_event(&raw).is_none());
    }

    #[test]
    fn unknown_correlation_is_not_emitted() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp(10);
        let raw = raw_ndis(frame);

        assert!(parser.parse(&raw).is_none());
    }

    #[test]
    fn truncated_frame_is_not_emitted() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let raw = raw_ndis(vec![0x00; 5]);

        assert!(parser.parse(&raw).is_none());
    }

    // --- Unit tests for extract_five_tuple ---

    #[test]
    fn extract_tuple_ipv4_tcp() {
        let frame = build_ethernet_ipv4_tcp(10);
        let tuple = extract_packet(&frame).expect("should extract").tuple;
        assert_eq!(tuple.src_ip, "10.0.0.1");
        assert_eq!(tuple.src_port, 1234);
        assert_eq!(tuple.dst_ip, "10.0.0.2");
        assert_eq!(tuple.dst_port, 80);
        assert_eq!(tuple.protocol, Protocol::Tcp);
    }

    #[test]
    fn extract_tuple_ipv6_udp() {
        let frame = build_ethernet_ipv6_udp(10);
        let tuple = extract_packet(&frame).expect("should extract").tuple;
        assert_eq!(tuple.src_ip, "::1");
        assert_eq!(tuple.src_port, 5678);
        assert_eq!(tuple.dst_ip, "::1");
        assert_eq!(tuple.dst_port, 443);
        assert_eq!(tuple.protocol, Protocol::Udp);
    }

    #[test]
    fn extract_tuple_rejects_truncated_ipv4_total_length() {
        let mut frame = build_ethernet_ipv4_tcp(10);
        let declared_len = u16::try_from(frame.len() - ETH_HDR_LEN + 5).expect("fits in u16");
        frame[ETH_HDR_LEN + 2..ETH_HDR_LEN + 4].copy_from_slice(&declared_len.to_be_bytes());

        assert!(extract_packet(&frame).is_none());
    }

    #[test]
    fn extract_tuple_rejects_truncated_ipv6_payload_length() {
        let mut frame = build_ethernet_ipv6_udp(10);
        let declared_payload_len = 24u16;
        frame[ETH_HDR_LEN + 4..ETH_HDR_LEN + 6]
            .copy_from_slice(&declared_payload_len.to_be_bytes());

        assert!(extract_packet(&frame).is_none());
    }

    #[test]
    fn extract_tuple_rejects_invalid_udp_length() {
        let mut frame = build_ethernet_ipv4_udp(&[1, 2, 3, 4], 53000, 53);
        let udp_offset = ETH_HDR_LEN + 20;
        frame[udp_offset + 4..udp_offset + 6].copy_from_slice(&6u16.to_be_bytes());

        assert!(extract_packet(&frame).is_none());
    }

    #[test]
    fn extract_tuple_too_short_returns_none() {
        assert!(extract_packet(&[0x00; 20]).is_none());
    }

    #[test]
    fn extract_tuple_non_ip_returns_none() {
        let mut frame = vec![0xFF; 6];
        frame.extend_from_slice(&[0xAA; 6]);
        frame.extend_from_slice(&[0x08, 0x01]); // unknown ethertype
        frame.extend_from_slice(&[0x00; 40]);
        assert!(extract_packet(&frame).is_none());
    }
}
