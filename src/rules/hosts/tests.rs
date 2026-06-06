//! # `rules::hosts::tests`
//!
//! **Purpose**: Unit tests for URL host rewrite rules.
//! **Public API**: test module only
//! **Dependencies**: `rules::hosts`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 92 / 140

use super::*;

#[test]
fn rewrites_matching_host_and_preserves_url_parts() {
    let rule = HostsRule::new(r"^old\.example\.com$", "127.0.0.1").expect("build hosts rule");

    let rewrite = rewrite_first_url("https://old.example.com:8443/api?q=1#frag", &[rule]);

    assert_eq!(rewrite.url, "https://127.0.0.1:8443/api?q=1#frag");
    assert_eq!(rewrite.matched_rule, Some(0));
}

#[test]
fn regex_capture_rewrites_host_only() {
    let rule =
        HostsRule::new(r"^api-(.+)\.example\.com$", "$1.internal").expect("build hosts rule");

    let rewrite = rewrite_first_url("http://api-edge.example.com/v1", &[rule]);

    assert_eq!(rewrite.url, "http://edge.internal/v1");
    assert_eq!(rewrite.matched_rule, Some(0));
}

#[test]
fn first_matching_rule_wins() {
    let first = HostsRule::new(r"example\.com$", "first.local").expect("build first rule");
    let second = HostsRule::new(r"^api\.example\.com$", "second.local").expect("build second rule");

    let rewrite = rewrite_first_url("https://api.example.com", &[first, second]);

    assert_eq!(rewrite.url, "https://api.first.local");
    assert_eq!(rewrite.matched_rule, Some(0));
}

#[test]
fn no_match_or_missing_host_returns_original_url() {
    let rule = HostsRule::new(r"^ads\.example\.com$", "127.0.0.1").expect("build hosts rule");

    let unchanged_host =
        rewrite_first_url("https://api.example.com/v1", std::slice::from_ref(&rule));
    let relative_path = rewrite_first_url("/api/example", &[rule]);

    assert_eq!(unchanged_host.url, "https://api.example.com/v1");
    assert_eq!(unchanged_host.matched_rule, None);
    assert_eq!(relative_path.url, "/api/example");
    assert_eq!(relative_path.matched_rule, None);
}

#[test]
fn matching_is_case_insensitive() {
    let rule = HostsRule::new(r"^api\.example\.com$", "edge.local").expect("build hosts rule");

    let rewrite = rewrite_first_url("https://API.EXAMPLE.COM/v1", &[rule]);

    assert_eq!(rewrite.url, "https://edge.local/v1");
}

#[test]
fn bracketed_ipv6_host_rewrites_inside_brackets() {
    let rule = HostsRule::new(r"^2001:db8::1$", "::1").expect("build hosts rule");

    let rewrite = rewrite_first_url("http://[2001:db8::1]:8080/health", &[rule]);

    assert_eq!(rewrite.url, "http://[::1]:8080/health");
    assert_eq!(rewrite.matched_rule, Some(0));
}

#[test]
fn invalid_pattern_returns_error() {
    let error = HostsRule::new("[", "127.0.0.1").expect_err("invalid regex");

    assert!(error.to_string().contains("invalid hosts pattern"));
}
