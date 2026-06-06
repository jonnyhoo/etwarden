//! # `rules::config::tests`
//!
//! **Purpose**: Unit tests for rules config decoding.
//! **Public API**: test module only
//! **Dependencies**: `rules::config`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 96 / 120

use super::*;

#[test]
fn json_config_decodes_utf8_replacement_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "type": "Bytes", "source": "old.example.com", "target": "new.example.com" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.decode_replace_rules().expect("decode rules");

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].source, b"old.example.com");
    assert_eq!(rules[0].target, b"new.example.com");
    assert_eq!(rules[0].rule_type, ReplacementRuleKind::Bytes);
}

#[test]
fn json_config_decodes_hex_file_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "type": "File", "source": "2f646f776e6c6f6164", "target": "66 69 6c 65", "encoding": "HEX" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.decode_replace_rules().expect("decode rules");

    assert_eq!(rules[0].source, b"/download");
    assert_eq!(rules[0].target, b"file");
    assert_eq!(rules[0].rule_type, ReplacementRuleKind::File);
}

#[test]
fn json_config_decodes_base64_rule() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "type": "Bytes", "source": "b2xk", "target": "bmV3", "encoding": "BASE64" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.decode_replace_rules().expect("decode rules");

    assert_eq!(rules[0].source, b"old");
    assert_eq!(rules[0].target, b"new");
    assert_eq!(rules[0].rule_type, ReplacementRuleKind::Bytes);
}

#[test]
fn invalid_hex_reports_index() {
    let config = ReplaceRuleConfig {
        rule_type: ReplacementRuleKind::Bytes,
        source: "4g".into(),
        target: "00".into(),
        encoding: RuleValueEncoding::Hex,
    };

    let error = config.decode().expect_err("invalid hex");

    assert_eq!(error.to_string(), "invalid hex digit 'g' at index 1");
}

#[test]
fn odd_hex_length_reports_digit_count() {
    let config = ReplaceRuleConfig {
        rule_type: ReplacementRuleKind::Bytes,
        source: "0ff".into(),
        target: "00".into(),
        encoding: RuleValueEncoding::Hex,
    };

    let error = config.decode().expect_err("odd hex length");

    assert_eq!(
        error.to_string(),
        "hex value must contain an even number of digits, got 3"
    );
}
