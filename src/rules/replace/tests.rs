//! # `rules::replace::tests`
//!
//! **Purpose**: Unit tests for byte and file replacement rule behavior.
//! **Public API**: test module only
//! **Dependencies**: `rules::replace`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 62 / 120

use super::*;

#[test]
fn byte_rule_replaces_all_occurrences() {
    let rules = [ReplaceRule::bytes(b"old".to_vec(), b"new".to_vec())];

    let outcome = apply_first(b"old.example/old", &rules);

    assert_eq!(outcome.payload, b"new.example/new");
    assert_eq!(outcome.matched_rules, 1);
    assert!(!outcome.file_replaced);
}

#[test]
fn file_rule_replaces_whole_payload() {
    let rules = [ReplaceRule::file(
        b"/download".to_vec(),
        b"file body".to_vec(),
    )];

    let outcome = apply_first(b"GET /download HTTP/1.1", &rules);

    assert_eq!(outcome.payload, b"file body");
    assert_eq!(outcome.matched_rules, 1);
    assert!(outcome.file_replaced);
}

#[test]
fn empty_source_never_matches() {
    let rules = [ReplaceRule::bytes(Vec::new(), b"x".to_vec())];

    let outcome = apply_all(b"abc", &rules);

    assert_eq!(outcome.payload, b"abc");
    assert_eq!(outcome.matched_rules, 0);
}

#[test]
fn apply_all_chains_byte_rules_until_file_rule() {
    let rules = [
        ReplaceRule::bytes(b"old".to_vec(), b"new".to_vec()),
        ReplaceRule::bytes(b"new.example".to_vec(), b"cdn.example".to_vec()),
        ReplaceRule::file(b"cdn.example".to_vec(), b"override".to_vec()),
        ReplaceRule::bytes(b"override".to_vec(), b"ignored".to_vec()),
    ];

    let outcome = apply_all(b"https://old.example/app", &rules);

    assert_eq!(outcome.payload, b"override");
    assert_eq!(outcome.matched_rules, 3);
    assert!(outcome.file_replaced);
}
