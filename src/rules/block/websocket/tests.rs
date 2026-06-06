//! # `rules::block::websocket::tests`
//!
//! **Purpose**: Unit tests for WebSocket block-rule evaluation.
//! **Public API**: test module only
//! **Dependencies**: `rules::block::websocket`, `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 178 / 200

use super::*;
use crate::rules::matcher::MatchOperator;

#[test]
fn matching_rule_blocks_connection() {
    let rule = WebSocketBlockRule::new(
        true,
        10,
        "GET",
        MatchOperator::Contains,
        "ws.example.com/chat",
        WebSocketBlockAction::CloseConnection,
    )
    .expect("build WebSocket block rule");
    let context = WebSocketBlockContext {
        method: "get",
        url: "wss://ws.example.com/chat/room",
    };

    let decision = evaluate_websocket_first(&context, &[rule]);

    assert_eq!(
        decision,
        WebSocketBlockDecision::Block {
            rule_index: 0,
            priority: 10,
            action: WebSocketBlockAction::CloseConnection,
        }
    );
}

#[test]
fn disabled_and_method_mismatched_rules_do_not_match() {
    let disabled = WebSocketBlockRule::new(
        false,
        1,
        "*",
        MatchOperator::Contains,
        "example.com",
        WebSocketBlockAction::CloseConnection,
    )
    .expect("build disabled rule");
    let post_only = WebSocketBlockRule::new(
        true,
        2,
        "POST",
        MatchOperator::Contains,
        "example.com",
        WebSocketBlockAction::DropUpstreamFrame,
    )
    .expect("build POST rule");
    let context = WebSocketBlockContext {
        method: "GET",
        url: "wss://example.com/socket",
    };

    assert_eq!(
        evaluate_websocket_first(&context, &[disabled, post_only]),
        WebSocketBlockDecision::Allow
    );
}

#[test]
fn wildcard_method_matches_any_method() {
    let rule = WebSocketBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::StartsWith,
        "wss://api.example.com/private",
        WebSocketBlockAction::DropDownstreamFrame,
    )
    .expect("build wildcard rule");
    let context = WebSocketBlockContext {
        method: "GET",
        url: "wss://api.example.com/private/stream",
    };

    assert!(rule.matches(&context));
}

#[test]
fn lower_priority_value_wins_over_order() {
    let first = WebSocketBlockRule::new(
        true,
        100,
        "*",
        MatchOperator::Contains,
        "example.com",
        WebSocketBlockAction::DropUpstreamFrame,
    )
    .expect("build first rule");
    let second = WebSocketBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Contains,
        "example.com",
        WebSocketBlockAction::DropDownstreamFrame,
    )
    .expect("build second rule");
    let context = WebSocketBlockContext {
        method: "GET",
        url: "wss://example.com/socket",
    };

    let decision = evaluate_websocket_first(&context, &[first, second]);

    assert_eq!(
        decision,
        WebSocketBlockDecision::Block {
            rule_index: 1,
            priority: 1,
            action: WebSocketBlockAction::DropDownstreamFrame,
        }
    );
}

#[test]
fn equal_priority_keeps_earlier_rule() {
    let first = WebSocketBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Contains,
        "example",
        WebSocketBlockAction::DropUpstreamFrame,
    )
    .expect("build first rule");
    let second = WebSocketBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Contains,
        "example",
        WebSocketBlockAction::DropDownstreamFrame,
    )
    .expect("build second rule");
    let context = WebSocketBlockContext {
        method: "GET",
        url: "wss://example.com/socket",
    };

    let decision = evaluate_websocket_first(&context, &[first, second]);

    assert_eq!(
        decision,
        WebSocketBlockDecision::Block {
            rule_index: 0,
            priority: 1,
            action: WebSocketBlockAction::DropUpstreamFrame,
        }
    );
}

#[test]
fn invalid_regex_pattern_is_rejected() {
    let error = WebSocketBlockRule::new(
        true,
        1,
        "*",
        MatchOperator::Regex,
        "[",
        WebSocketBlockAction::CloseConnection,
    )
    .expect_err("invalid regex");

    assert!(error.to_string().contains("invalid regex pattern"));
}
