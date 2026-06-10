//! # `divert::packet::tests::udp`
//!
//! **Purpose**: Unit tests for IPv4/UDP packet parsing boundaries.
//! **Public API**: test module only
//! **Dependencies**: `divert::packet`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 48 / 80

use std::net::SocketAddrV4;

use super::super::*;

fn build_udp_packet(src: &SocketAddrV4, dst: &SocketAddrV4) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[9] = IP_PROTO_UDP;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
    pkt
}

#[test]
fn parse_valid_udp_datagram() {
    let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
    let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 53);
    let pkt = build_udp_packet(&src, &dst);

    let parsed = parse_ipv4_udp(&pkt).expect("should parse");

    assert_eq!((parsed.src_ip, parsed.src_port), (*src.ip(), src.port()));
    assert_eq!((parsed.dst_ip, parsed.dst_port), (*dst.ip(), dst.port()));
}

#[test]
fn udp_length_cannot_exceed_ipv4_total_length() {
    let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000);
    let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 53);
    let mut pkt = build_udp_packet(&src, &dst);
    pkt.extend_from_slice(&[0, 0, 0, 0]);
    pkt[24..26].copy_from_slice(&12u16.to_be_bytes());

    assert!(parse_ipv4_udp(&pkt).is_none());
}
