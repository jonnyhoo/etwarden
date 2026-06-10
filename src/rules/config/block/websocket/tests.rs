//! # `rules::config::block::websocket::tests`
//!
//! **Purpose**: Unit tests for WebSocket block config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::{block, config, matcher}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 110 / 120

use super::*;
use crate::rules::{
    block::websocket::{evaluate_websocket_first, WebSocketBlockContext, WebSocketBlockDecision},
    config::RulesConfig,
    matcher::MatchError,
};

#[test]
fn json_config_builds_websocket_block_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "block_rules": {
                "websocket": [
                    {
                        "enable": true,
                        "priority": 1,
                        "method": "GET",
                        "url_pattern": "ws\\.example\\.com",
                        "action": "断开连接"
                    },
                    {
                        "enable": true,
                        "priority": 2,
                        "method": "GET",
                        "url_pattern": "up\\.example\\.com",
                        "action": "丢弃上行帧"
                    },
                    {
                        "enable": true,
                        "priority": 3,
                        "method": "GET",
                        "url_pattern": "down\\.example\\.com",
                        "action": "丢弃下行帧"
                    }
                ]
            }
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_websocket_block_rules()
        .expect("build WebSocket block rules");
    let decision = evaluate_websocket_first(
        &WebSocketBlockContext {
            method: "GET",
            url: "wss://ws.example.com/socket",
        },
        &rules,
    );

    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].url_operator, MatchOperator::Regex);
    assert_eq!(rules[1].action, WebSocketBlockAction::DropUpstreamFrame);
    assert_eq!(rules[2].action, WebSocketBlockAction::DropDownstreamFrame);
    assert_eq!(
        decision,
        WebSocketBlockDecision::Block {
            rule_index: 0,
            priority: 1,
            action: WebSocketBlockAction::CloseConnection,
        }
    );
}

#[test]
fn json_config_accepts_roadmap_url_match_type_alias() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "block_rules": {
                "websocket": [
                    { "enable": true, "priority": 1, "method": "GET", "url_match_type": "前缀", "url_pattern": "wss://ws.example.com", "action": "CloseConnection" }
                ]
            }
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_websocket_block_rules()
        .expect("build WebSocket block rules");

    assert_eq!(rules[0].url_operator, MatchOperator::StartsWith);
}

#[test]
fn invalid_websocket_block_regex_is_rejected() {
    let config = WebSocketBlockRuleConfig {
        enable: true,
        priority: 1,
        method: "GET".into(),
        url_operator: MatchOperator::Regex,
        url_pattern: "(".into(),
        action: WebSocketBlockAction::CloseConnection,
    };

    let error = config.build().expect_err("invalid regex");

    assert!(matches!(error, MatchError::RegexCompile(_)));
}
