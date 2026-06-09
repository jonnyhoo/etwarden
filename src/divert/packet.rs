//! # `divert::packet`
//!
//! **Purpose**: Minimal IP/TCP header parsing and address rewrite for packet redirect.
//! **Public API**: `ParsedPacket`, `parse_ipv4_tcp`, rewrite helpers
//! **Dependencies**: `std`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 170 / 190

use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// IP header (20 bytes, no options)
// ---------------------------------------------------------------------------

const IP_PROTO_TCP: u8 = 6;

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

/// TCP flags.
pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

/// Parses an IPv4+TCP packet and extracts the 5-tuple + header lengths.
///
/// Returns `None` if the packet is too short, not IPv4, not TCP, or has
/// truncated headers.
pub fn parse_ipv4_tcp(packet: &[u8]) -> Option<ParsedPacket> {
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
    if protocol != IP_PROTO_TCP {
        return None;
    }

    let src_ip = Ipv4Addr::from(u32::from_be_bytes([
        packet[12], packet[13], packet[14], packet[15],
    ]));
    let dst_ip = Ipv4Addr::from(u32::from_be_bytes([
        packet[16], packet[17], packet[18], packet[19],
    ]));

    let tcp_offset = ip_header_len as usize;
    if packet.len() < tcp_offset + 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
    let tcp_flags = packet[tcp_offset + 13];
    let data_offset = (packet[tcp_offset + 12] >> 4) * 4;
    if data_offset < 20 {
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
mod tests {
    use std::net::SocketAddrV4;

    use super::*;

    /// Builds a minimal IPv4+TCP SYN packet for testing.
    fn build_syn_packet(src: &SocketAddrV4, dst: &SocketAddrV4) -> Vec<u8> {
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
                                     // IP header
        pkt[0] = 0x45; // version=4, IHL=5 (20 bytes)
        pkt[9] = IP_PROTO_TCP;
        pkt[12..16].copy_from_slice(&src.ip().octets());
        pkt[16..20].copy_from_slice(&dst.ip().octets());
        // TCP header
        let tcp_off = 20;
        pkt[tcp_off..tcp_off + 2].copy_from_slice(&src.port().to_be_bytes());
        pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst.port().to_be_bytes());
        pkt[tcp_off + 12] = 0x50; // data offset = 5 (20 bytes)
        pkt[tcp_off + 13] = TCP_SYN;
        pkt
    }

    #[test]
    fn parse_valid_syn() {
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        let pkt = build_syn_packet(&src, &dst);
        let parsed = parse_ipv4_tcp(&pkt).expect("should parse");
        assert_eq!(parsed.src_ip, *src.ip());
        assert_eq!(parsed.dst_ip, *dst.ip());
        assert_eq!(parsed.src_port, src.port());
        assert_eq!(parsed.dst_port, dst.port());
        assert_eq!(parsed.tcp_flags, TCP_SYN);
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(parse_ipv4_tcp(&[0x45; 10]).is_none());
    }

    #[test]
    fn parse_non_tcp_returns_none() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        assert!(parse_ipv4_tcp(&pkt).is_none());
    }

    #[test]
    fn rewrite_changes_dst() {
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        let mut pkt = build_syn_packet(&src, &dst);

        let new_ip = Ipv4Addr::LOCALHOST;
        assert!(rewrite_tcp_dst(&mut pkt, new_ip, 3003, 20));

        let parsed = parse_ipv4_tcp(&pkt).expect("should still parse");
        assert_eq!(parsed.dst_ip, new_ip);
        assert_eq!(parsed.dst_port, 3003);
        assert_eq!(parsed.src_ip, *src.ip());
        assert_eq!(parsed.src_port, src.port());
    }

    #[test]
    fn rewrite_changes_src_and_dst() {
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80);
        let mut pkt = build_syn_packet(&src, &dst);

        assert!(rewrite_tcp_addrs(
            &mut pkt,
            dst.ip().to_owned(),
            src.port(),
            src.ip().to_owned(),
            3003,
            20
        ));

        let parsed = parse_ipv4_tcp(&pkt).expect("should still parse");
        assert_eq!(parsed.src_ip, *dst.ip());
        assert_eq!(parsed.src_port, src.port());
        assert_eq!(parsed.dst_ip, *src.ip());
        assert_eq!(parsed.dst_port, 3003);
    }
}
