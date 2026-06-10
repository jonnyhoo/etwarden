//! # `divert::redirect::socket_block::tests`
//!
//! **Purpose**: Unit tests for active socket block decisions.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect::socket_block`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 80

use super::*;
use crate::rules::{
    block::socket::{SocketBlockRule, SocketProtocol},
    matcher::MatchOperator,
};

fn rule(action: SocketBlockAction) -> SocketBlockRule {
    SocketBlockRule::new(
        true,
        10,
        SocketProtocol::Tcp,
        MatchOperator::Equals,
        "93.184.216.34:443",
        action,
    )
    .expect("rule")
}

#[test]
fn tcp_syn_block_action_enforces_disconnect_and_drop_upstream_only() {
    let blocked = RuleSet {
        tcp_block: vec![rule(SocketBlockAction::Disconnect)],
        ..RuleSet::default()
    };
    let upstream = RuleSet {
        tcp_block: vec![rule(SocketBlockAction::DropUpstream)],
        ..RuleSet::default()
    };
    let deferred = RuleSet {
        tcp_block: vec![rule(SocketBlockAction::DropDownstream)],
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
