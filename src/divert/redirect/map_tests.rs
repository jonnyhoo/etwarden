//! # `divert::redirect::map_tests`
//!
//! **Purpose**: Unit tests for redirect map packet-peer matching.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect`, `divert::packet`, `divert::redirect_map`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 54 / 80

use std::net::Ipv4Addr;

use super::proxy_reply_dest;
use crate::divert::{
    packet::{ParsedPacket, TCP_ACK},
    OriginalDest, RedirectMap,
};

#[test]
fn proxy_reply_lookup_rejects_wrong_local_ip() {
    let map = RedirectMap::new();
    let local_ip = Ipv4Addr::new(192, 168, 1, 100);
    let remote_ip = Ipv4Addr::new(93, 184, 216, 34);
    map.insert(51000, original_dest(local_ip, remote_ip));

    let wrong_local = proxy_reply_packet(Ipv4Addr::new(192, 168, 1, 101), remote_ip);
    assert!(proxy_reply_dest(&map, &wrong_local, 3003).is_none());

    let expected_local = proxy_reply_packet(local_ip, remote_ip);
    assert_eq!(
        proxy_reply_dest(&map, &expected_local, 3003).map(|d| d.local_ip),
        Some(local_ip)
    );
}

fn proxy_reply_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> ParsedPacket {
    ParsedPacket {
        src_ip,
        dst_ip,
        src_port: 3003,
        dst_port: 51000,
        ip_header_len: 20,
        tcp_header_len: 20,
        tcp_flags: TCP_ACK,
    }
}

fn original_dest(local_ip: Ipv4Addr, ip: Ipv4Addr) -> OriginalDest {
    OriginalDest {
        local_ip,
        ip,
        port: 443,
        pid: 4242,
    }
}
