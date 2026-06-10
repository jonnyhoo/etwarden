//! # `rules::config::block::strict_tests`
//!
//! **Purpose**: Strict-deserialization tests for block rule groups.
//! **Public API**: test module only
//! **Dependencies**: `rules::config`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 19 / 80

use crate::rules::config::RulesConfig;

#[test]
fn unknown_block_rule_groups_are_rejected() {
    let error = serde_json::from_str::<RulesConfig>(r#"{"block_rules":{"httpp":[]}}"#)
        .expect_err("unknown block rule group");

    assert!(error.to_string().contains("httpp"));
}
