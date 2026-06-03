//! # `parser::ndis`
//!
//! **Purpose**: Parses Microsoft-Windows-NDIS-PacketCapture ETW events into `NetEvent::RawCapture`.
//! **Public API**: `struct NdisParser` (implements `EventParser`)
//! **Dependencies**: `parser::types`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 180 / 220

use std::sync::Arc;

use windows::core::GUID;

use crate::{
    parser::{
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
/// Each event contains a raw Ethernet frame. The parser wraps it in
/// `NetEvent::RawCapture` and attempts to resolve the owning PID via the
/// shared `Correlator` by extracting the five-tuple from IP/TCP/UDP headers.
pub struct NdisParser {
    correlator: Arc<Correlator>,
}

impl NdisParser {
    /// Creates a new `NdisParser` with the given correlator for PID resolution.
    #[must_use]
    pub const fn new(correlator: Arc<Correlator>) -> Self {
        Self { correlator }
    }
}

impl EventParser for NdisParser {
    fn provider_guid(&self) -> GUID {
        GUID::from(PROVIDER_NDIS)
    }

    fn parse(&self, raw: &RawEvent) -> Option<NetEvent> {
        let frame = RawFrame {
            timestamp: raw.timestamp,
            data: raw.data.clone(),
        };

        let pid = extract_five_tuple(&raw.data)
            .and_then(|tuple| self.correlator.resolve_pid(&tuple))
            .unwrap_or(raw.pid);

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

/// Extracts a `FiveTuple` from raw Ethernet frame bytes.
///
/// Parses Ethernet → IP → TCP/UDP headers to find src/dst IP and port.
/// Returns `None` if the frame is too short or uses an unsupported protocol.
fn extract_five_tuple(frame: &[u8]) -> Option<FiveTuple> {
    if frame.len() < ETH_HDR_LEN + 20 {
        return None;
    }

    let eth_type = &frame[12..14];
    if eth_type == ETHERTYPE_IPV4 {
        parse_ipv4_tuple(&frame[ETH_HDR_LEN..])
    } else if eth_type == ETHERTYPE_IPV6 {
        parse_ipv6_tuple(&frame[ETH_HDR_LEN..])
    } else {
        None
    }
}

/// Parses IPv4 + TCP/UDP headers to extract a five-tuple.
fn parse_ipv4_tuple(ip: &[u8]) -> Option<FiveTuple> {
    if ip.len() < 20 {
        return None;
    }

    let ihl = usize::from(ip[0] & 0x0F) * 4;
    let protocol = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let transport = ip.get(ihl..)?;
    parse_transport(transport, protocol, src_ip, dst_ip)
}

/// Parses IPv6 + TCP/UDP headers to extract a five-tuple.
fn parse_ipv6_tuple(ip: &[u8]) -> Option<FiveTuple> {
    if ip.len() < 40 {
        return None;
    }

    let protocol = ip[6];
    let src_ip = format_ipv6(&ip[8..24]);
    let dst_ip = format_ipv6(&ip[24..40]);

    parse_transport(&ip[40..], protocol, src_ip, dst_ip)
}

/// Parses TCP/UDP transport header for port numbers.
fn parse_transport(
    transport: &[u8],
    protocol: u8,
    src_ip: String,
    dst_ip: String,
) -> Option<FiveTuple> {
    if transport.len() < 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

    let proto = match protocol {
        IPPROTO_TCP => Protocol::Tcp,
        IPPROTO_UDP => Protocol::Udp,
        _ => return None,
    };

    Some(FiveTuple {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: proto,
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
        frame.extend_from_slice(&[0u8; 16]); // seq + ack + flags + window + checksum + urgent
                                             // payload
        frame.extend_from_slice(&vec![0xDD; payload_len]);
        frame
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
    fn unknown_correlation_falls_back_to_raw_pid() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp(10);
        let raw = raw_ndis(frame);

        let event = parser.parse(&raw).expect("should parse");
        match event {
            NetEvent::RawCapture { pid, .. } => assert_eq!(pid, 99), // raw.pid
            _ => unreachable!("expected RawCapture"),
        }
    }

    #[test]
    fn truncated_frame_still_produces_event() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let raw = raw_ndis(vec![0x00; 5]);

        let event = parser.parse(&raw).expect("should parse");
        match event {
            NetEvent::RawCapture { pid, .. } => assert_eq!(pid, 99),
            _ => unreachable!("expected RawCapture"),
        }
    }

    // --- Unit tests for extract_five_tuple ---

    #[test]
    fn extract_tuple_ipv4_tcp() {
        let frame = build_ethernet_ipv4_tcp(10);
        let tuple = extract_five_tuple(&frame).expect("should extract");
        assert_eq!(tuple.src_ip, "10.0.0.1");
        assert_eq!(tuple.src_port, 1234);
        assert_eq!(tuple.dst_ip, "10.0.0.2");
        assert_eq!(tuple.dst_port, 80);
        assert_eq!(tuple.protocol, Protocol::Tcp);
    }

    #[test]
    fn extract_tuple_ipv6_udp() {
        let frame = build_ethernet_ipv6_udp(10);
        let tuple = extract_five_tuple(&frame).expect("should extract");
        assert_eq!(tuple.src_ip, "::1");
        assert_eq!(tuple.src_port, 5678);
        assert_eq!(tuple.dst_ip, "::1");
        assert_eq!(tuple.dst_port, 443);
        assert_eq!(tuple.protocol, Protocol::Udp);
    }

    #[test]
    fn extract_tuple_too_short_returns_none() {
        assert!(extract_five_tuple(&[0x00; 20]).is_none());
    }

    #[test]
    fn extract_tuple_non_ip_returns_none() {
        let mut frame = vec![0xFF; 6];
        frame.extend_from_slice(&[0xAA; 6]);
        frame.extend_from_slice(&[0x08, 0x01]); // unknown ethertype
        frame.extend_from_slice(&[0x00; 40]);
        assert!(extract_five_tuple(&frame).is_none());
    }
}
