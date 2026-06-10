//! # `divert::packet`
//!
//! **Purpose**: Minimal IP/TCP/UDP header parsing and address rewrite for packet redirect.
//! **Public API**: packet parse/rewrite helpers
//! **Dependencies**: `std`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 188 / 190

use std::net::Ipv4Addr;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// Minimal parsed fields from an IPv4+TCP packet.
pub struct ParsedPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_header_len: u8,
    pub tcp_header_len: u8,
    pub tcp_flags: u8,
}

/// Minimal parsed fields from an IPv4+UDP packet.
pub struct ParsedUdpPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_header_len: u8,
    pub udp_len: u16,
}

/// TCP flags.
pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

/// Parses an IPv4+TCP packet and extracts the 5-tuple + header lengths.
///
/// Returns `None` if the packet is too short, not IPv4, not TCP, or has
/// truncated headers.
pub fn parse_ipv4_tcp(packet: &[u8]) -> Option<ParsedPacket> {
    let (ip_header_len, src_ip, dst_ip) = parse_ipv4_header(packet, IP_PROTO_TCP)?;

    let tcp_offset = ip_header_len as usize;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < tcp_offset + 20 || packet.len() < total_len {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
    let tcp_flags = packet[tcp_offset + 13];
    let data_offset = (packet[tcp_offset + 12] >> 4) * 4;
    if data_offset < 20 || tcp_offset + usize::from(data_offset) > total_len {
        return None;
    }

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ip_header_len,
        tcp_header_len: data_offset,
        tcp_flags,
    })
}

/// Parses an IPv4+UDP packet and extracts the 5-tuple + UDP length.
///
/// Returns `None` if the packet is too short, not IPv4, not UDP, or has a
/// truncated UDP datagram.
pub fn parse_ipv4_udp(packet: &[u8]) -> Option<ParsedUdpPacket> {
    let (ip_header_len, src_ip, dst_ip) = parse_ipv4_header(packet, IP_PROTO_UDP)?;
    let udp_offset = ip_header_len as usize;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < udp_offset + 8 || packet.len() < total_len {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[udp_offset], packet[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]);
    let udp_len = u16::from_be_bytes([packet[udp_offset + 4], packet[udp_offset + 5]]);
    let udp_len_usize = usize::from(udp_len);
    if udp_len_usize < 8 || udp_offset + udp_len_usize > total_len {
        return None;
    }

    Some(ParsedUdpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ip_header_len,
        udp_len,
    })
}

fn parse_ipv4_header(packet: &[u8], expected_protocol: u8) -> Option<(u8, Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }

    let version_ihl = packet[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return None;
    }
    let ip_header_len = (version_ihl & 0x0F) * 4;
    if ip_header_len < 20 || packet.len() < ip_header_len as usize {
        return None;
    }

    let protocol = packet[9];
    if protocol != expected_protocol {
        return None;
    }

    let src_ip = Ipv4Addr::from(u32::from_be_bytes([
        packet[12], packet[13], packet[14], packet[15],
    ]));
    let dst_ip = Ipv4Addr::from(u32::from_be_bytes([
        packet[16], packet[17], packet[18], packet[19],
    ]));

    Some((ip_header_len, src_ip, dst_ip))
}

/// Rewrites the destination IP and port in an IPv4+TCP packet buffer.
///
/// After calling this, the caller must recalculate checksums via
/// `WinDivertHelperCalcChecksums`.
///
/// # Panics
/// Does not panic — returns `false` if the packet is too short.
pub fn rewrite_tcp_dst(
    packet: &mut [u8],
    new_dst_ip: Ipv4Addr,
    new_dst_port: u16,
    ip_header_len: u8,
) -> bool {
    let ip_hl = ip_header_len as usize;
    if packet.len() < ip_hl + 20 {
        return false;
    }

    // Rewrite destination IP (bytes 16-19 of IP header).
    let octets = new_dst_ip.octets();
    packet[16] = octets[0];
    packet[17] = octets[1];
    packet[18] = octets[2];
    packet[19] = octets[3];

    // Rewrite destination port (bytes 2-3 of TCP header).
    let port = new_dst_port.to_be_bytes();
    packet[ip_hl + 2] = port[0];
    packet[ip_hl + 3] = port[1];

    true
}

/// Rewrites source/destination IPv4 addresses and TCP ports in an IPv4+TCP packet buffer.
pub fn rewrite_tcp_addrs(
    packet: &mut [u8],
    new_src_ip: Ipv4Addr,
    new_src_port: u16,
    new_dst_ip: Ipv4Addr,
    new_dst_port: u16,
    ip_header_len: u8,
) -> bool {
    let ip_hl = ip_header_len as usize;
    if packet.len() < ip_hl + 20 {
        return false;
    }

    packet[12..16].copy_from_slice(&new_src_ip.octets());
    packet[16..20].copy_from_slice(&new_dst_ip.octets());
    packet[ip_hl..ip_hl + 2].copy_from_slice(&new_src_port.to_be_bytes());
    packet[ip_hl + 2..ip_hl + 4].copy_from_slice(&new_dst_port.to_be_bytes());

    true
}

#[cfg(test)]
mod tests;
