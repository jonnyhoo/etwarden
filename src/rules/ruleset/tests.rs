//! # `rules::ruleset::tests`
//!
//! **Purpose**: Unit tests for compiled rule set construction.
//! **Public API**: test module only
//! **Dependencies**: `rules::{block, config, ruleset}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 54 / 80

use super::*;
use crate::rules::{
    block::socket::{
        evaluate_socket_first, SocketBlockAction, SocketBlockContext, SocketBlockDecision,
        SocketProtocol,
    },
    config::RulesConfig,
};

#[test]
fn build_preserves_socket_block_rules() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "block_rules": {
                "tcp": [
                    { "enable": true, "priority": 1, "address_pattern": "10\\.0\\.0\\.7:443", "action": "Disconnect" }
                ],
                "udp": [
                    { "enable": true, "priority": 2, "address_pattern": "8\\.8\\.8\\.8:53", "action": "DropUpstream" }
                ]
            }
        }"#,
    )
    .expect("parse rules config");

    let rules = RuleSet::build(&config).expect("build rule set");
    let decision = evaluate_socket_first(
        &SocketBlockContext {
            protocol: SocketProtocol::Udp,
            address: "8.8.8.8:53",
        },
        &rules.udp_block,
    );

    assert_eq!(rules.tcp_block.len(), 1);
    assert_eq!(
        decision,
        SocketBlockDecision::Block {
            rule_index: 0,
            priority: 2,
            action: SocketBlockAction::DropUpstream,
        }
    );
}
