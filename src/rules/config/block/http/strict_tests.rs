//! # `rules::config::block::http::strict_tests`
//!
//! **Purpose**: Strict-deserialization tests for HTTP block config.
//! **Public API**: test module only
//! **Dependencies**: `rules::config`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 21 / 80

use crate::rules::config::RulesConfig;

#[test]
fn unknown_http_block_rule_fields_are_rejected() {
    let error = serde_json::from_str::<RulesConfig>(
        r#"{"block_rules":{"http":[{"enable":true,"priority":1,"method":"*","url_pattern":"tracker","url_match_typo":"包含","action":"CloseRequest"}]}}"#,
    )
    .expect_err("unknown HTTP block field");

    assert!(error.to_string().contains("url_match_typo"));
}
