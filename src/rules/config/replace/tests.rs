//! # `rules::config::replace::tests`
//!
//! **Purpose**: Unit tests for replacement config builders.
//! **Public API**: test module only
//! **Dependencies**: `rules::{config, replace}`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 88 / 100

use crate::rules::{config::RulesConfig, replace::apply_all};

#[test]
fn json_config_builds_replacement_rules() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "type": "Bytes", "source": "old.example.com", "target": "new.example.com" },
                { "type": "File", "source": "/download", "target": "file" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.build_replace_rules().expect("build replace rules");
    let outcome = apply_all(b"/download old.example.com", &rules);

    assert_eq!(rules.len(), 2);
    assert_eq!(outcome.payload, b"file");
    assert_eq!(outcome.matched_rules, 2);
    assert!(outcome.file_replaced);
}

#[test]
fn json_config_accepts_roadmap_rule_type_field() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "rule_type": "Bytes", "source": "old", "target": "new" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.build_replace_rules().expect("build replace rules");
    let outcome = apply_all(b"old", &rules);

    assert_eq!(outcome.payload, b"new");
    assert_eq!(outcome.matched_rules, 1);
}

#[test]
fn json_config_accepts_roadmap_value_type_field() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "rule_type": "Bytes", "source": "6f6c64", "target": "6e6577", "value_type": "HEX" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.build_replace_rules().expect("build replace rules");
    let outcome = apply_all(b"old", &rules);

    assert_eq!(outcome.payload, b"new");
    assert_eq!(outcome.matched_rules, 1);
}

#[test]
fn json_config_accepts_roadmap_replace_kind_names() {
    let config: RulesConfig = serde_json::from_str(
        r#"{
            "replace_rules": [
                { "rule_type": "字节替换", "source": "old", "target": "new" },
                { "rule_type": "文件替换", "source": "/download", "target": "file" }
            ]
        }"#,
    )
    .expect("parse rules config");

    let rules = config.build_replace_rules().expect("build replace rules");
    let outcome = apply_all(b"/download old", &rules);

    assert_eq!(outcome.payload, b"file");
    assert_eq!(outcome.matched_rules, 2);
    assert!(outcome.file_replaced);
}
