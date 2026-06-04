//! # `parser::ndis::transport`
//!
//! **Purpose**: Extracts TCP/UDP ports and payload slices from transport headers.
//! **Public API**: module-private transport parser
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 120

use crate::parser::types::Protocol;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

pub(super) struct ParsedTransport<'a> {
    pub(super) protocol: Protocol,
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) payload: &'a [u8],
}

pub(super) fn parse_transport_packet(
    transport: &[u8],
    protocol: u8,
) -> Option<ParsedTransport<'_>> {
    if transport.len() < 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    let (protocol, payload) = match protocol {
        IPPROTO_TCP => parse_tcp_payload(transport)?,
        IPPROTO_UDP => parse_udp_payload(transport)?,
        _ => return None,
    };

    Some(ParsedTransport {
        protocol,
        src_port,
        dst_port,
        payload,
    })
}

fn parse_tcp_payload(transport: &[u8]) -> Option<(Protocol, &[u8])> {
    if transport.len() < 20 {
        return None;
    }
    let data_offset = usize::from(transport[12] >> 4) * 4;
    if data_offset < 20 || transport.len() < data_offset {
        return None;
    }
    Some((Protocol::Tcp, &transport[data_offset..]))
}

fn parse_udp_payload(transport: &[u8]) -> Option<(Protocol, &[u8])> {
    if transport.len() < 8 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([transport[4], transport[5]]));
    if udp_len < 8 || udp_len > transport.len() {
        return None;
    }
    Some((Protocol::Udp, &transport[8..udp_len]))
}
