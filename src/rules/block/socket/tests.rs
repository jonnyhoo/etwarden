//! # `rules::block::socket::tests`
//!
//! **Purpose**: Unit tests for socket block-rule evaluation.
//! **Public API**: test module only
//! **Dependencies**: `rules::block::socket`, `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 180 / 200

use super::*;
use crate::rules::matcher::MatchOperator;

fn rule(
    enable: bool,
    priority: u32,
    protocol: SocketProtocol,
    address_pattern: &str,
    action: SocketBlockAction,
) -> SocketBlockRule {
    SocketBlockRule::new(
        enable,
        priority,
        protocol,
        MatchOperator::Contains,
        address_pattern,
        action,
    )
    .expect("build socket block rule")
}

#[test]
fn matching_rule_blocks_socket() {
    let block = rule(
        true,
        10,
        SocketProtocol::Tcp,
        "10.0.0.7:443",
        SocketBlockAction::Disconnect,
    );
    let context = SocketBlockContext {
        protocol: SocketProtocol::Tcp,
        address: "10.0.0.7:443",
    };

    let decision = evaluate_socket_first(&context, &[block]);

    assert_eq!(
        decision,
        SocketBlockDecision::Block {
            rule_index: 0,
            priority: 10,
            action: SocketBlockAction::Disconnect,
        }
    );
}

#[test]
fn disabled_and_protocol_mismatched_rules_do_not_match() {
    let disabled = rule(
        false,
        1,
        SocketProtocol::Tcp,
        "example.com:443",
        SocketBlockAction::Disconnect,
    );
    let udp_only = rule(
        true,
        2,
        SocketProtocol::Udp,
        "example.com:443",
        SocketBlockAction::DropUpstream,
    );
    let context = SocketBlockContext {
        protocol: SocketProtocol::Tcp,
        address: "example.com:443",
    };

    assert_eq!(
        evaluate_socket_first(&context, &[disabled, udp_only]),
        SocketBlockDecision::Allow
    );
}

#[test]
fn address_matching_is_case_insensitive() {
    let block = rule(
        true,
        1,
        SocketProtocol::Tcp,
        "api.example.com:443",
        SocketBlockAction::DropDownstream,
    );
    let context = SocketBlockContext {
        protocol: SocketProtocol::Tcp,
        address: "API.EXAMPLE.COM:443",
    };

    assert!(block.matches(&context));
}

#[test]
fn lower_priority_value_wins_over_order() {
    let first = rule(
        true,
        100,
        SocketProtocol::Udp,
        "8.8.8.8:53",
        SocketBlockAction::DropUpstream,
    );
    let second = rule(
        true,
        1,
        SocketProtocol::Udp,
        "8.8.8.8:53",
        SocketBlockAction::DropDownstream,
    );
    let context = SocketBlockContext {
        protocol: SocketProtocol::Udp,
        address: "8.8.8.8:53",
    };

    let decision = evaluate_socket_first(&context, &[first, second]);

    assert_eq!(
        decision,
        SocketBlockDecision::Block {
            rule_index: 1,
            priority: 1,
            action: SocketBlockAction::DropDownstream,
        }
    );
}

#[test]
fn equal_priority_keeps_earlier_rule() {
    let first = rule(
        true,
        1,
        SocketProtocol::Tcp,
        "example.com:443",
        SocketBlockAction::Disconnect,
    );
    let second = rule(
        true,
        1,
        SocketProtocol::Tcp,
        "example.com:443",
        SocketBlockAction::DropUpstream,
    );
    let context = SocketBlockContext {
        protocol: SocketProtocol::Tcp,
        address: "example.com:443",
    };

    let decision = evaluate_socket_first(&context, &[first, second]);

    assert_eq!(
        decision,
        SocketBlockDecision::Block {
            rule_index: 0,
            priority: 1,
            action: SocketBlockAction::Disconnect,
        }
    );
}

#[test]
fn invalid_regex_pattern_is_rejected() {
    let error = SocketBlockRule::new(
        true,
        1,
        SocketProtocol::Tcp,
        MatchOperator::Regex,
        "[",
        SocketBlockAction::Disconnect,
    )
    .expect_err("invalid regex");

    assert!(error.to_string().contains("invalid regex pattern"));
}
