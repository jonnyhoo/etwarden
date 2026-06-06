//! # `rules::matcher::tests`

use super::{MatchOperator, TextMatcher};

#[test]
fn equals_matches_ascii_case_insensitively() {
    let matcher = TextMatcher::new(MatchOperator::Equals, "Example.COM").expect("build matcher");

    assert!(matcher.matches("example.com"));
    assert!(!matcher.matches("api.example.com"));
}

#[test]
fn contains_matches_ascii_case_insensitively() {
    let matcher = TextMatcher::new(MatchOperator::Contains, "Token").expect("build matcher");

    assert!(matcher.matches("bearer token value"));
    assert!(!matcher.matches("bearer value"));
}

#[test]
fn prefix_and_suffix_match_ascii_case_insensitively() {
    let prefix = TextMatcher::new(MatchOperator::StartsWith, "api.").expect("build prefix matcher");
    let suffix = TextMatcher::new(MatchOperator::EndsWith, ".local").expect("build suffix matcher");

    assert!(prefix.matches("API.example.local"));
    assert!(suffix.matches("api.example.LOCAL"));
    assert!(!prefix.matches("edge.api.example.local"));
    assert!(!suffix.matches("api.example.net"));
}

#[test]
fn regex_compiles_once_and_matches_case_insensitively() {
    let matcher = TextMatcher::new(MatchOperator::Regex, r"^api-[0-9]+\.example\.com$")
        .expect("build regex matcher");

    assert!(matcher.matches("API-42.example.com"));
    assert!(!matcher.matches("api.example.com"));
}

#[test]
fn invalid_regex_returns_error() {
    let error = TextMatcher::new(MatchOperator::Regex, "[").expect_err("invalid regex");

    assert!(error.to_string().contains("invalid regex pattern"));
}

#[test]
fn empty_patterns_never_match() {
    for operator in [
        MatchOperator::Equals,
        MatchOperator::Contains,
        MatchOperator::Regex,
        MatchOperator::StartsWith,
        MatchOperator::EndsWith,
    ] {
        let matcher = TextMatcher::new(operator, "").expect("build empty matcher");

        assert!(!matcher.matches("anything"));
    }
}
