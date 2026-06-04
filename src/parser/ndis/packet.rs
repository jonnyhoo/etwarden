//! # `parser::ndis::packet`
//!
//! **Purpose**: Extracts TCP/UDP metadata and payloads from Ethernet/IP packets.
//! **Public API**: `extract_packet`, `ParsedPacket`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 190 / 260

use super::transport::parse_transport_packet;
use crate::parser::types::FiveTuple;

/// Parsed packet metadata extracted from an Ethernet frame.
pub(super) struct ParsedPacket<'a> {
    pub(super) tuple: FiveTuple,
    pub(super) payload: &'a [u8],
}

const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xDD];
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;
const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

/// Extracts a `FiveTuple` and payload slice from raw Ethernet frame bytes.
pub(super) fn extract_packet(frame: &[u8]) -> Option<ParsedPacket<'_>> {
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

fn parse_ipv4_packet(ip: &[u8]) -> Option<ParsedPacket<'_>> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }

    let ihl = usize::from(ip[0] & 0x0F) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }

    let flags_fragment = u16::from_be_bytes([ip[6], ip[7]]);
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = flags_fragment & 0x1FFF;
    if more_fragments || fragment_offset != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if total_len < ihl || total_len > ip.len() {
        return None;
    }

    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let transport = parse_transport_packet(ip.get(ihl..total_len)?, ip[9])?;
    Some(ParsedPacket {
        tuple: FiveTuple {
            src_ip,
            src_port: transport.src_port,
            dst_ip,
            dst_port: transport.dst_port,
            protocol: transport.protocol,
        },
        payload: transport.payload,
    })
}

fn parse_ipv6_packet(ip: &[u8]) -> Option<ParsedPacket<'_>> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let payload_end = 40usize.checked_add(payload_len)?;
    if payload_end > ip.len() {
        return None;
    }

    let src_ip = format_ipv6(&ip[8..24]);
    let dst_ip = format_ipv6(&ip[24..40]);
    let (protocol, transport) = ipv6_transport_slice(ip, payload_end)?;

    let transport = parse_transport_packet(transport, protocol)?;
    Some(ParsedPacket {
        tuple: FiveTuple {
            src_ip,
            src_port: transport.src_port,
            dst_ip,
            dst_port: transport.dst_port,
            protocol: transport.protocol,
        },
        payload: transport.payload,
    })
}

fn ipv6_transport_slice(ip: &[u8], payload_end: usize) -> Option<(u8, &[u8])> {
    let mut protocol = ip[6];
    let mut offset = 40;
    let mut headers_seen = 0;

    while is_ipv6_extension_header(protocol) {
        headers_seen += 1;
        if headers_seen > MAX_IPV6_EXTENSION_HEADERS {
            return None;
        }
        let header = ip.get(offset..payload_end)?;
        match protocol {
            IPPROTO_FRAGMENT => {
                if header.len() < 8 {
                    return None;
                }
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                let offset_units = (fragment >> 3) & 0x1FFF;
                let more_fragments = fragment & 0x0001 != 0;
                if offset_units != 0 || more_fragments {
                    return None;
                }
                protocol = header[0];
                offset = offset.checked_add(8)?;
            }
            IPPROTO_AH => {
                if header.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(header[1]) + 2).checked_mul(4)?;
                if header_len < 8 || header_len > header.len() {
                    return None;
                }
                protocol = header[0];
                offset = offset.checked_add(header_len)?;
            }
            _ => {
                if header.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(header[1]) + 1).checked_mul(8)?;
                if header_len < 8 || header_len > header.len() {
                    return None;
                }
                protocol = header[0];
                offset = offset.checked_add(header_len)?;
            }
        }
    }

    Some((protocol, ip.get(offset..payload_end)?))
}

const fn is_ipv6_extension_header(protocol: u8) -> bool {
    matches!(
        protocol,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_FRAGMENT | IPPROTO_AH | IPPROTO_DSTOPTS
    )
}

fn format_ipv6(bytes: &[u8]) -> String {
    use std::net::Ipv6Addr;
    let arr: [u8; 16] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    Ipv6Addr::from(arr).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{
        ndis::test_support::{
            build_ethernet_ipv4_tcp, build_ethernet_ipv4_udp, build_ethernet_ipv6_udp,
        },
        types::Protocol,
    };

    const IPPROTO_UDP: u8 = 17;

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
    fn extract_tuple_ipv6_udp_after_extension_header() {
        let mut frame = build_ethernet_ipv6_udp(10);
        let ipv6 = ETH_HDR_LEN;
        let payload_len = u16::from_be_bytes([frame[ipv6 + 4], frame[ipv6 + 5]]);
        frame[ipv6 + 4..ipv6 + 6].copy_from_slice(&payload_len.saturating_add(8).to_be_bytes());
        frame[ipv6 + 6] = IPPROTO_HOPOPTS;
        frame.splice(ipv6 + 40..ipv6 + 40, [IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);

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
    fn extract_tuple_rejects_ipv4_more_fragments() {
        let mut frame = build_ethernet_ipv4_tcp(10);
        frame[ETH_HDR_LEN + 6..ETH_HDR_LEN + 8].copy_from_slice(&0x2000u16.to_be_bytes());

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
    fn extract_tuple_rejects_invalid_ipv6_version() {
        let mut frame = build_ethernet_ipv6_udp(10);
        frame[ETH_HDR_LEN] = 0x40;

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
        frame.extend_from_slice(&[0x08, 0x01]);
        frame.extend_from_slice(&[0x00; 40]);
        assert!(extract_packet(&frame).is_none());
    }
}
