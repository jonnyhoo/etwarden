//! # `rules::config::hosts::tests`
//!
//! **Purpose**: Unit tests for hosts config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::config`, `rules::hosts`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 54 / 80

use super::*;
use crate::rules::{
    config::RulesConfig,
    hosts::{rewrite_first_url, HostsRuleError},
};

#[test]
fn json_config_builds_hosts_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "hosts_rules": [
                { "pattern": ".*\\.example\\.com", "target": "127.0.0.1" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.build_hosts_rules().expect("build hosts rules");
    let rewrite = rewrite_first_url("https://api.example.com/path", &rules);

    assert_eq!(rules.len(), 1);
    assert_eq!(rewrite.url, "https://127.0.0.1/path");
    assert_eq!(rewrite.matched_rule, Some(0));
}

#[test]
fn invalid_hosts_regex_is_rejected() {
    let config = RulesConfig {
        hosts_rules: vec![HostsRuleConfig {
            pattern: "(".into(),
            target: "127.0.0.1".into(),
        }],
        ..RulesConfig::default()
    };

    let error = config.build_hosts_rules().expect_err("invalid regex");

    assert!(matches!(error, HostsRuleError::RegexCompile(_)));
}
