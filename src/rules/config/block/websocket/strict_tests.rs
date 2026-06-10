//! # `rules::config::block::websocket::strict_tests`
//!
//! **Purpose**: Strict-deserialization tests for WebSocket block config.
//! **Public API**: test module only
//! **Dependencies**: `rules::config`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 21 / 80

use crate::rules::config::RulesConfig;

#[test]
fn unknown_websocket_block_rule_fields_are_rejected() {
    let error = serde_json::from_str::<RulesConfig>(
        r#"{"block_rules":{"websocket":[{"enable":true,"priority":1,"method":"GET","url_pattern":"ws","url_match_typo":"前缀","action":"CloseConnection"}]}}"#,
    )
    .expect_err("unknown WebSocket block field");

    assert!(error.to_string().contains("url_match_typo"));
}
