//! # `divert::packet::tests::tcp`
//!
//! **Purpose**: Unit tests for IPv4/TCP packet parsing boundaries.
//! **Public API**: test module only
//! **Dependencies**: `divert::packet`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 48 / 80

use std::net::SocketAddrV4;

use super::*;

fn endpoint_pair() -> (SocketAddrV4, SocketAddrV4) {
    (
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 51000),
        SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443),
    )
}

#[test]
fn parse_truncated_tcp_options_returns_none() {
    let (src, dst) = endpoint_pair();
    let mut pkt = build_syn_packet(&src, &dst);
    pkt[32] = 0xF0;

    assert!(parse_ipv4_tcp(&pkt).is_none());
}

#[test]
fn tcp_header_cannot_exceed_ipv4_total_length() {
    let (src, dst) = endpoint_pair();
    let mut pkt = build_syn_packet(&src, &dst);
    pkt.extend_from_slice(&[0, 0, 0, 0]);
    pkt[32] = 0x60;

    assert!(parse_ipv4_tcp(&pkt).is_none());
}

#[test]
fn tcp_fragment_is_not_parsed() {
    let (src, dst) = endpoint_pair();
    let mut pkt = build_syn_packet(&src, &dst);
    pkt[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

    assert!(parse_ipv4_tcp(&pkt).is_none());
}
