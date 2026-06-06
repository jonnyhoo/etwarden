//! # `rules::config::block::socket::tests`
//!
//! **Purpose**: Unit tests for socket block config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::{block, config, matcher}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 95 / 120

use super::*;
use crate::rules::{
    block::socket::{evaluate_socket_first, SocketBlockContext, SocketBlockDecision},
    config::RulesConfig,
    matcher::MatchError,
};

#[test]
fn json_config_builds_tcp_and_udp_block_rules() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "block_rules": {
                "tcp": [
                    {
                        "enable": true,
                        "priority": 1,
                        "address_pattern": "10\\.0\\.0\\.7:443",
                        "action": "Disconnect"
                    }
                ],
                "udp": [
                    {
                        "enable": true,
                        "priority": 2,
                        "address_pattern": "8\\.8\\.8\\.8:53",
                        "action": "DropUpstream"
                    }
                ]
            }
        }"#,
    )
    .expect("parse rules config");

    let tcp_rules = config.build_tcp_block_rules().expect("build TCP rules");
    let udp_rules = config.build_udp_block_rules().expect("build UDP rules");
    let tcp_decision = evaluate_socket_first(
        &SocketBlockContext {
            protocol: SocketProtocol::Tcp,
            address: "10.0.0.7:443",
        },
        &tcp_rules,
    );
    let udp_decision = evaluate_socket_first(
        &SocketBlockContext {
            protocol: SocketProtocol::Udp,
            address: "8.8.8.8:53",
        },
        &udp_rules,
    );

    assert_eq!(tcp_rules[0].address_operator, MatchOperator::Regex);
    assert_eq!(udp_rules[0].address_operator, MatchOperator::Regex);
    assert_eq!(
        tcp_decision,
        SocketBlockDecision::Block {
            rule_index: 0,
            priority: 1,
            action: SocketBlockAction::Disconnect,
        }
    );
    assert_eq!(
        udp_decision,
        SocketBlockDecision::Block {
            rule_index: 0,
            priority: 2,
            action: SocketBlockAction::DropUpstream,
        }
    );
}

#[test]
fn invalid_socket_block_regex_is_rejected() {
    let config = SocketBlockRuleConfig {
        enable: true,
        priority: 1,
        address_operator: MatchOperator::Regex,
        address_pattern: "(".into(),
        action: SocketBlockAction::Disconnect,
    };

    let error = config
        .build(SocketProtocol::Tcp)
        .expect_err("invalid regex");

    assert!(matches!(error, MatchError::RegexCompile(_)));
}
