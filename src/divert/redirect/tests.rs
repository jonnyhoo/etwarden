//! # `divert::redirect::tests`
//!
//! **Purpose**: Unit tests for WinDivert redirect helpers.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect`, `rules`, `parser`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 116 / 120

use super::*;
use crate::{
    divert::redirect::flow::flow_keys_from_tuples,
    parser::types::Protocol,
    rules::{
        block::socket::{SocketBlockAction, SocketBlockRule, SocketProtocol},
        matcher::MatchOperator,
        ruleset::RuleSet,
    },
};

fn tuple(src_port: u16, dst_ip: &str, dst_port: u16, protocol: Protocol) -> FiveTuple {
    FiveTuple {
        src_ip: "192.168.1.100".into(),
        src_port,
        dst_ip: dst_ip.into(),
        dst_port,
        protocol,
    }
}

#[test]
fn existing_ipv4_tcp_tuple_seeds_flow_key() {
    let tuple = tuple(51_000, "93.184.216.34", 443, Protocol::Tcp);

    let keys = flow_keys_from_tuples(&[tuple]);

    assert!(keys.contains_key(&FlowKey {
        local_port: 51_000,
        remote_ip: [93, 184, 216, 34],
        remote_port: 443,
    }));
}

#[test]
fn non_ipv4_or_non_tcp_tuple_is_not_seeded() {
    let tuples = [
        tuple(
            51_000,
            "2606:2800:220:1:248:1893:25c8:1946",
            443,
            Protocol::Tcp,
        ),
        tuple(51_001, "93.184.216.34", 53, Protocol::Udp),
    ];

    assert!(flow_keys_from_tuples(&tuples).is_empty());
}

#[test]
fn network_filter_supports_port_include_and_exclude() {
    let filter = build_network_filter(3003, &[80, 443], &[16669]);

    assert!(filter.contains("ip"));
    assert!(filter.contains("tcp.DstPort == 80"));
    assert!(filter.contains("tcp.DstPort == 443"));
    assert!(filter.contains("tcp.DstPort != 16669"));
    assert!(filter.contains("tcp.SrcPort == 3003"));
}

#[test]
fn network_filter_keeps_loopback_eligible() {
    let filter = build_network_filter(3003, &[], &[]);

    assert!(!filter.contains("127.0.0.1"));
    assert!(filter.contains("tcp.DstPort != 3003"));
}

#[test]
fn tcp_syn_block_action_enforces_disconnect_and_drop_upstream_only() {
    let disconnect = SocketBlockRule::new(
        true,
        10,
        SocketProtocol::Tcp,
        MatchOperator::Equals,
        "93.184.216.34:443",
        SocketBlockAction::Disconnect,
    )
    .expect("rule");
    let drop_downstream = SocketBlockRule::new(
        true,
        10,
        SocketProtocol::Tcp,
        MatchOperator::Equals,
        "93.184.216.34:443",
        SocketBlockAction::DropDownstream,
    )
    .expect("rule");

    let blocked = RuleSet {
        tcp_block: vec![disconnect],
        ..RuleSet::default()
    };
    let deferred = RuleSet {
        tcp_block: vec![drop_downstream],
        ..RuleSet::default()
    };

    assert_eq!(
        tcp_syn_block_action(Some(&blocked), Ipv4Addr::new(93, 184, 216, 34), 443),
        Some(SocketBlockAction::Disconnect),
    );
    assert_eq!(
        tcp_syn_block_action(Some(&deferred), Ipv4Addr::new(93, 184, 216, 34), 443),
        None,
    );
}
