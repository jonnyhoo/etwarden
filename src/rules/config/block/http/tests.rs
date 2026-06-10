//! # `rules::config::block::http::tests`
//!
//! **Purpose**: Unit tests for HTTP block config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::{block, config, matcher}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 111 / 120

use super::*;
use crate::rules::{
    block::http::{evaluate_http_first, HttpBlockContext, HttpBlockDecision},
    config::RulesConfig,
    matcher::MatchError,
};

#[test]
fn json_config_builds_http_block_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "block_rules": {
                "http": [
                    {
                        "enable": true,
                        "priority": 1,
                        "method": "*",
                        "url_pattern": "tracker\\.ad\\.com",
                        "action": "CloseRequest"
                    }
                ],
                "websocket": [],
                "tcp": [],
                "udp": []
            }
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_http_block_rules()
        .expect("build HTTP block rules");
    let decision = evaluate_http_first(
        &HttpBlockContext {
            method: "GET",
            url: "https://tracker.ad.com/pixel",
        },
        &rules,
    );

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].url_operator, MatchOperator::Regex);
    assert_eq!(
        decision,
        HttpBlockDecision::Block {
            rule_index: 0,
            priority: 1,
            action: HttpBlockAction::CloseRequest,
        }
    );
}

#[test]
fn json_config_accepts_roadmap_url_match_type_names() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "block_rules": {
                "http": [
                    { "enable": true, "priority": 1, "method": "*", "url_match_type": "包含", "url_pattern": "tracker", "action": "CloseRequest" },
                    { "enable": true, "priority": 2, "method": "*", "url_match_type": "前缀", "url_pattern": "https://", "action": "CloseRequest" },
                    { "enable": true, "priority": 3, "method": "*", "url_match_type": "正则", "url_pattern": "ad\\d+", "action": "CloseRequest" },
                    { "enable": true, "priority": 4, "method": "*", "url_match_type": "完全匹配", "url_pattern": "https://exact.example/", "action": "CloseRequest" }
                ]
            }
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_http_block_rules()
        .expect("build HTTP block rules");

    assert_eq!(
        rules
            .iter()
            .map(|rule| rule.url_operator)
            .collect::<Vec<_>>(),
        vec![
            MatchOperator::Contains,
            MatchOperator::StartsWith,
            MatchOperator::Regex,
            MatchOperator::Equals,
        ]
    );
}

#[test]
fn invalid_http_block_regex_is_rejected() {
    let config = HttpBlockRuleConfig {
        enable: true,
        priority: 1,
        method: "*".into(),
        url_operator: MatchOperator::Regex,
        url_pattern: "(".into(),
        action: HttpBlockAction::CloseRequest,
    };

    let error = config.build().expect_err("invalid regex");

    assert!(matches!(error, MatchError::RegexCompile(_)));
}
