//! # `divert::redirect::socket_block::tests`
//!
//! **Purpose**: Unit tests for active socket block decisions.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect::socket_block`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 79 / 80

use super::*;
use crate::rules::{
    block::socket::{SocketBlockRule, SocketProtocol},
    matcher::MatchOperator,
};

fn rule(protocol: SocketProtocol, priority: u32, action: SocketBlockAction) -> SocketBlockRule {
    SocketBlockRule::new(
        true,
        priority,
        protocol,
        MatchOperator::Equals,
        "93.184.216.34:443",
        action,
    )
    .expect("rule")
}

#[test]
fn tcp_syn_block_action_enforces_disconnect_and_drop_upstream_only() {
    let blocked = RuleSet {
        tcp_block: vec![rule(SocketProtocol::Tcp, 10, SocketBlockAction::Disconnect)],
        ..RuleSet::default()
    };
    let upstream = RuleSet {
        tcp_block: vec![rule(
            SocketProtocol::Tcp,
            10,
            SocketBlockAction::DropUpstream,
        )],
        ..RuleSet::default()
    };
    let deferred = RuleSet {
        tcp_block: vec![rule(
            SocketProtocol::Tcp,
            10,
            SocketBlockAction::DropDownstream,
        )],
        ..RuleSet::default()
    };

    assert_eq!(
        tcp_syn_block_action(Some(&blocked), Ipv4Addr::new(93, 184, 216, 34), 443),
        Some(SocketBlockAction::Disconnect),
    );
    assert_eq!(
        tcp_syn_block_action(Some(&upstream), Ipv4Addr::new(93, 184, 216, 34), 443),
        Some(SocketBlockAction::DropUpstream),
    );
    assert_eq!(
        tcp_syn_block_action(Some(&deferred), Ipv4Addr::new(93, 184, 216, 34), 443),
        None,
    );
}

#[test]
fn udp_datagram_block_action_uses_udp_rules() {
    let rules = RuleSet {
        udp_block: vec![
            rule(SocketProtocol::Udp, 1, SocketBlockAction::DropDownstream),
            rule(SocketProtocol::Udp, 10, SocketBlockAction::DropUpstream),
        ],
        ..RuleSet::default()
    };

    assert_eq!(
        udp_datagram_block_action(Some(&rules), Ipv4Addr::new(93, 184, 216, 34), 443),
        Some(SocketBlockAction::DropUpstream),
    );
}
