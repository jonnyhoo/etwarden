//! # `divert::redirect::flow_tests`
//!
//! **Purpose**: Unit tests for redirect flow-key boundaries.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect`, `parser`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 74 / 80

use std::net::Ipv4Addr;

use super::flow::{flow_keys_from_tuples, remove_redirect_for_flow_deleted, FlowKey};
use crate::{
    divert::{OriginalDest, RedirectMap},
    parser::types::{FiveTuple, Protocol},
};

#[test]
fn flow_key_distinguishes_same_port_on_different_local_ips() {
    let tuples = [
        tuple("192.168.1.100", 51_000, "93.184.216.34", 443),
        tuple("192.168.1.101", 51_000, "93.184.216.34", 443),
    ];

    let keys = flow_keys_from_tuples(&tuples);

    assert_eq!(keys.len(), 2);
}

#[test]
fn flow_deleted_removes_only_matching_redirect_entry() {
    let map = RedirectMap::new();
    let local_ip = [192, 168, 1, 100];
    let remote_ip = [93, 184, 216, 34];
    map.insert(51_000, original_dest(local_ip, remote_ip));

    let wrong_local = flow_key([192, 168, 1, 101], 51_000, remote_ip, 443);
    assert!(!remove_redirect_for_flow_deleted(&map, &wrong_local));
    assert!(map.get(51_000).is_some());

    let exact = flow_key(local_ip, 51_000, remote_ip, 443);
    assert!(remove_redirect_for_flow_deleted(&map, &exact));
    assert!(map.get(51_000).is_none());
}

fn tuple(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> FiveTuple {
    FiveTuple {
        src_ip: src_ip.into(),
        src_port,
        dst_ip: dst_ip.into(),
        dst_port,
        protocol: Protocol::Tcp,
    }
}

fn flow_key(local_ip: [u8; 4], local_port: u16, remote_ip: [u8; 4], remote_port: u16) -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
    }
}

fn original_dest(local_ip: [u8; 4], ip: [u8; 4]) -> OriginalDest {
    OriginalDest {
        local_ip: Ipv4Addr::from(local_ip),
        ip: Ipv4Addr::from(ip),
        port: 443,
        pid: 4242,
    }
}
