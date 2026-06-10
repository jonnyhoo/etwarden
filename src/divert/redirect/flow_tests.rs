//! # `divert::redirect::flow_tests`
//!
//! **Purpose**: Unit tests for redirect flow-key boundaries.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect`, `parser`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 33 / 80

use super::flow::flow_keys_from_tuples;
use crate::parser::types::{FiveTuple, Protocol};

#[test]
fn flow_key_distinguishes_same_port_on_different_local_ips() {
    let tuples = [
        tuple("192.168.1.100", 51_000, "93.184.216.34", 443),
        tuple("192.168.1.101", 51_000, "93.184.216.34", 443),
    ];

    let keys = flow_keys_from_tuples(&tuples);

    assert_eq!(keys.len(), 2);
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
