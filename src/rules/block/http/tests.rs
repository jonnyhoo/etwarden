//! # `rules::block::http::tests`
//!
//! **Purpose**: Unit tests for HTTP block-rule evaluation.
//! **Public API**: test module only
//! **Dependencies**: `rules::block::http`, `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 178 / 200

use super::*;
use crate::rules::matcher::MatchOperator;

#[test]
fn matching_rule_blocks_request() {
    let rule = HttpBlockRule::new(
        true,
        10,
        "GET",
        MatchOperator::Contains,
        "tracker.example.com",
        HttpBlockAction::CloseRequest,
    )
    .expect("build HTTP block rule");
    let context = HttpBlockContext {
        method: "get",
        url: "https://tracker.example.com/pixel",
    };

    let decision = evaluate_http_first(&context, &[rule]);

    assert_eq!(
        decision,
        HttpBlockDecision::Block {
            rule_index: 0,
            priority: 10,
            action: HttpBlockAction::CloseRequest,
        }
    );
}

#[test]
fn disabled_and_method_mismatched_rules_do_not_match() {
    let disabled = HttpBlockRule::new(
        false,
        1,
        "*",
        MatchOperator::Contains,
        "example.com",
        HttpBlockAction::CloseRequest,
    )
    .expect("build disabled rule");
    let post_only = HttpBlockRule::new(
        true,
        2,
        "POST",
        MatchOperator::Contains,
        "example.com",
        HttpBlockAction::CloseRequest,
    )
    .expect("build POST rule");
    let context = HttpBlockContext {
        method: "GET",
        url: "https://example.com",
    };

    assert_eq!(
        evaluate_http_first(&context, &[disabled, post_only]),
        HttpBlockDecision::Allow
    );
}

#[test]
fn wildcard_method_matches_any_method() {
    let rule = HttpBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::StartsWith,
        "https://api.example.com/private",
        HttpBlockAction::CloseResponse,
    )
    .expect("build wildcard rule");
    let context = HttpBlockContext {
        method: "PATCH",
        url: "https://api.example.com/private/1",
    };

    assert!(rule.matches(&context));
}

#[test]
fn lower_priority_value_wins_over_order() {
    let first = HttpBlockRule::new(
        true,
        100,
        "*",
        MatchOperator::Contains,
        "example.com",
        HttpBlockAction::CloseRequest,
    )
    .expect("build first rule");
    let second = HttpBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Contains,
        "example.com",
        HttpBlockAction::CloseResponse,
    )
    .expect("build second rule");
    let context = HttpBlockContext {
        method: "GET",
        url: "https://example.com",
    };

    let decision = evaluate_http_first(&context, &[first, second]);

    assert_eq!(
        decision,
        HttpBlockDecision::Block {
            rule_index: 1,
            priority: 1,
            action: HttpBlockAction::CloseResponse,
        }
    );
}

#[test]
fn equal_priority_keeps_earlier_rule() {
    let first = HttpBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Contains,
        "example",
        HttpBlockAction::CloseRequest,
    )
    .expect("build first rule");
    let second = HttpBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Contains,
        "example",
        HttpBlockAction::CloseResponse,
    )
    .expect("build second rule");
    let context = HttpBlockContext {
        method: "GET",
        url: "https://example.com",
    };

    let decision = evaluate_http_first(&context, &[first, second]);

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
fn invalid_regex_pattern_is_rejected() {
    let error = HttpBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Regex,
        "[",
        HttpBlockAction::CloseRequest,
    )
    .expect_err("invalid regex");

    assert!(error.to_string().contains("invalid regex pattern"));
}
