//! # `rules::intercept::tests`
//!
//! **Purpose**: Unit tests for pure intercept-rule evaluation.
//! **Public API**: test module only
//! **Dependencies**: `rules::intercept`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 96 / 140

use super::*;
use crate::rules::matcher::MatchOperator;

#[test]
fn url_rule_returns_first_matching_action() {
    let rule = InterceptRule::new(
        true,
        "drop ads",
        InterceptDirection::Both,
        InterceptTarget::Url,
        MatchOperator::Contains,
        "ads.example.com",
        InterceptAction::Drop,
        "test rule",
    )
    .expect("build intercept rule");
    let context = InterceptContext {
        direction: InterceptDirection::Upstream,
        url: Some("https://ads.example.com/pixel"),
        ..InterceptContext::default()
    };

    let decision = evaluate_first(&context, &[rule]);

    assert_eq!(
        decision,
        InterceptDecision::Intercept {
            rule_index: 0,
            action: InterceptAction::Drop,
        }
    );
}

#[test]
fn disabled_and_direction_mismatched_rules_do_not_match() {
    let disabled = InterceptRule::new(
        false,
        "disabled",
        InterceptDirection::Both,
        InterceptTarget::Url,
        MatchOperator::Contains,
        "example.com",
        InterceptAction::Drop,
        "",
    )
    .expect("build disabled rule");
    let downstream = InterceptRule::new(
        true,
        "downstream",
        InterceptDirection::Downstream,
        InterceptTarget::Url,
        MatchOperator::Contains,
        "example.com",
        InterceptAction::Disconnect,
        "",
    )
    .expect("build downstream rule");
    let context = InterceptContext {
        direction: InterceptDirection::Upstream,
        url: Some("https://example.com"),
        ..InterceptContext::default()
    };

    let decision = evaluate_first(&context, &[disabled, downstream]);

    assert_eq!(decision, InterceptDecision::Allow);
}

#[test]
fn pid_and_process_name_targets_match_textually() {
    let pid = InterceptRule::new(
        true,
        "pid",
        InterceptDirection::Both,
        InterceptTarget::Pid,
        MatchOperator::Equals,
        "4242",
        InterceptAction::Pause,
        "",
    )
    .expect("build pid rule");
    let process = InterceptRule::new(
        true,
        "process",
        InterceptDirection::Both,
        InterceptTarget::ProcessName,
        MatchOperator::EndsWith,
        "browser.exe",
        InterceptAction::Drop,
        "",
    )
    .expect("build process rule");
    let context = InterceptContext {
        direction: InterceptDirection::Downstream,
        pid: Some(4242),
        process_name: Some("TestBrowser.EXE"),
        ..InterceptContext::default()
    };

    assert!(pid.matches(&context));
    assert!(process.matches(&context));
}

#[test]
fn missing_target_text_does_not_match() {
    let rule = InterceptRule::new(
        true,
        "missing body",
        InterceptDirection::Both,
        InterceptTarget::Body,
        MatchOperator::Contains,
        "secret",
        InterceptAction::Drop,
        "",
    )
    .expect("build body rule");
    let context = InterceptContext::default();

    assert!(!rule.matches(&context));
}

#[test]
fn invalid_regex_pattern_is_rejected() {
    let error = InterceptRule::new(
        true,
        "bad regex",
        InterceptDirection::Both,
        InterceptTarget::Header,
        MatchOperator::Regex,
        "[",
        InterceptAction::Drop,
        "",
    )
    .expect_err("invalid regex");

    assert!(error.to_string().contains("invalid regex pattern"));
}
