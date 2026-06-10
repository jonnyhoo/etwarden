//! # `rules::config::intercept::tests`
//!
//! **Purpose**: Unit tests for intercept config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::{config, intercept, matcher}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 140

use super::*;
use crate::rules::{
    config::RulesConfig,
    intercept::{evaluate_first, InterceptContext, InterceptDecision, InterceptDirection},
    matcher::MatchError,
};

#[test]
fn json_config_builds_intercept_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "intercept_rules": [
                {
                    "enable": true,
                    "direction": "Both",
                    "target": "URL",
                    "operator": "Contains",
                    "value": "ads.example.com",
                    "action": "Drop"
                }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_intercept_rules()
        .expect("build intercept rules");
    let decision = evaluate_first(
        &InterceptContext {
            direction: InterceptDirection::Upstream,
            url: Some("https://ads.example.com/banner"),
            ..InterceptContext::default()
        },
        &rules,
    );

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "");
    assert_eq!(rules[0].note, "");
    assert_eq!(
        decision,
        InterceptDecision::Intercept {
            rule_index: 0,
            action: InterceptAction::Drop,
        }
    );
}

#[test]
fn json_config_accepts_roadmap_intercept_action_names() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "intercept_rules": [
                { "enable": true, "direction": "Both", "target": "URL", "operator": "Contains", "value": "drop.example", "action": "丢弃" },
                { "enable": true, "direction": "Both", "target": "URL", "operator": "Contains", "value": "disconnect.example", "action": "断开" },
                { "enable": true, "direction": "Both", "target": "URL", "operator": "Contains", "value": "pause.example", "action": "断点暂停" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_intercept_rules()
        .expect("build intercept rules");

    assert_eq!(rules[0].action, InterceptAction::Drop);
    assert_eq!(rules[1].action, InterceptAction::Disconnect);
    assert_eq!(rules[2].action, InterceptAction::Pause);
}

#[test]
fn json_config_accepts_roadmap_direction_names() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "intercept_rules": [
                { "enable": true, "direction": "上行", "target": "URL", "operator": "Contains", "value": "upload.example", "action": "Drop" },
                { "enable": true, "direction": "下行", "target": "URL", "operator": "Contains", "value": "download.example", "action": "Drop" },
                { "enable": true, "direction": "双向", "target": "URL", "operator": "Contains", "value": "both.example", "action": "Drop" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config
        .build_intercept_rules()
        .expect("build intercept rules");

    assert_eq!(rules[0].direction, InterceptDirection::Upstream);
    assert_eq!(rules[1].direction, InterceptDirection::Downstream);
    assert_eq!(rules[2].direction, InterceptDirection::Both);
}

#[test]
fn invalid_intercept_regex_is_rejected() {
    let config = InterceptRuleConfig {
        enable: true,
        name: String::new(),
        direction: InterceptDirection::Both,
        target: InterceptTarget::Url,
        operator: MatchOperator::Regex,
        value: "(".into(),
        action: InterceptAction::Drop,
        note: String::new(),
    };

    let error = config.build().expect_err("invalid regex");

    assert!(matches!(error, MatchError::RegexCompile(_)));
}
