//! # `divert::packet::tests`
//!
//! **Purpose**: Unit tests for IPv4/TCP packet parsing and rewrite helpers.
//! **Public API**: test module only
//! **Dependencies**: `divert::packet`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 120

use std::net::SocketAddrV4;

use super::*;

/// Builds a minimal IPv4+TCP SYN packet for testing.
fn build_syn_packet(src: &SocketAddrV4, dst: &SocketAddrV4) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[9] = IP_PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());
    let tcp_off = 20;
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&src.port().to_be_bytes());
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst.port().to_be_bytes());
    pkt[tcp_off + 12] = 0x50;
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
fn parse_valid_udp_datagram() {
    let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
    let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 53);
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[9] = IP_PROTO_UDP;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[24..26].copy_from_slice(&8u16.to_be_bytes());

    let parsed = parse_ipv4_udp(&pkt).expect("should parse");

    assert_eq!((parsed.src_ip, parsed.src_port), (*src.ip(), src.port()));
    assert_eq!((parsed.dst_ip, parsed.dst_port), (*dst.ip(), dst.port()));
}

#[test]
fn parse_too_short_returns_none() {
    assert!(parse_ipv4_tcp(&[0x45; 10]).is_none());
}

#[test]
fn parse_non_tcp_returns_none() {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[9] = 17;
    assert!(parse_ipv4_tcp(&pkt).is_none());
}

#[test]
fn parse_truncated_tcp_options_returns_none() {
    let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
    let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
    let mut pkt = build_syn_packet(&src, &dst);
    pkt[32] = 0xF0;

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
        20,
    ));

    let parsed = parse_ipv4_tcp(&pkt).expect("should still parse");
    assert_eq!(parsed.src_ip, *dst.ip());
    assert_eq!(parsed.src_port, src.port());
    assert_eq!(parsed.dst_ip, *src.ip());
    assert_eq!(parsed.dst_port, 3003);
}
