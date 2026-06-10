//! # `divert::redirect::map_tests`
//!
//! **Purpose**: Unit tests for redirect map packet-peer matching.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect`, `divert::packet`, `divert::redirect_map`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 79 / 80

use std::net::Ipv4Addr;

use super::{client_redirect_dest, proxy_reply_dest};
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

#[test]
fn client_redirect_lookup_rejects_wrong_local_ip() {
    let map = RedirectMap::new();
    let local_ip = Ipv4Addr::new(192, 168, 1, 100);
    let remote_ip = Ipv4Addr::new(93, 184, 216, 34);
    map.insert(51000, original_dest(local_ip, remote_ip));

    let wrong_local = client_packet(Ipv4Addr::new(192, 168, 1, 101), remote_ip);
    assert!(client_redirect_dest(&map, &wrong_local).is_none());

    let expected_local = client_packet(local_ip, remote_ip);
    assert_eq!(
        client_redirect_dest(&map, &expected_local).map(|d| d.local_ip),
        Some(local_ip)
    );
}

fn proxy_reply_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> ParsedPacket {
    packet(src_ip, dst_ip, 3003, 51000)
}

fn client_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> ParsedPacket {
    packet(src_ip, dst_ip, 51000, 443)
}

fn packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> ParsedPacket {
    ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
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
