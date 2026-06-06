//! # `rules::config::intercept::tests`
//!
//! **Purpose**: Unit tests for intercept config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::{config, intercept, matcher}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 74 / 100

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
