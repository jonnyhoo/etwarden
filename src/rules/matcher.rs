//! # `rules::matcher`
//!
//! **Purpose**: Reusable text matcher for traffic-control rule targets.
//! **Public API**: `MatchOperator`, `TextMatcher`, `MatchError`
//! **Dependencies**: `regex`, `serde`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 86 / 160

#[cfg(test)]
mod tests;

use regex::{Regex, RegexBuilder};

/// Text match operation used by traffic-control rules.
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum MatchOperator {
    /// ASCII-case-insensitive equality.
    Equals,
    /// ASCII-case-insensitive substring match.
    Contains,
    /// Case-insensitive regular expression match.
    Regex,
    /// ASCII-case-insensitive prefix match.
    StartsWith,
    /// ASCII-case-insensitive suffix match.
    EndsWith,
}

/// Compiled text matcher for one rule condition.
#[derive(Debug, Clone)]
pub struct TextMatcher {
    operator: MatchOperator,
    pattern: String,
    regex: Option<Regex>,
}

/// Text matcher construction error.
#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    /// Regex pattern failed to compile.
    #[error("invalid regex pattern: {0}")]
    RegexCompile(#[from] regex::Error),
}

impl TextMatcher {
    /// Builds a matcher from an operator and pattern.
    ///
    /// # Arguments
    /// * `operator` — Matching operation.
    /// * `pattern` — Pattern used by the operation. Empty patterns never match.
    ///
    /// # Returns
    /// A compiled `TextMatcher`.
    ///
    /// # Errors
    /// Returns `MatchError` when a regex pattern cannot compile.
    pub fn new(operator: MatchOperator, pattern: impl Into<String>) -> Result<Self, MatchError> {
        let pattern = pattern.into();
        let regex = if matches!(operator, MatchOperator::Regex) {
            Some(case_insensitive_regex(&pattern)?)
        } else {
            None
        };

        Ok(Self {
            operator,
            pattern,
            regex,
        })
    }

    /// Checks whether `value` matches this matcher.
    ///
    /// # Arguments
    /// * `value` — Candidate text to test.
    ///
    /// # Returns
    /// `true` when the matcher condition is satisfied.
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        if self.pattern.is_empty() {
            return false;
        }

        match self.operator {
            MatchOperator::Equals => value.eq_ignore_ascii_case(&self.pattern),
            MatchOperator::Contains => contains_ignore_ascii_case(value, &self.pattern),
            MatchOperator::Regex => self
                .regex
                .as_ref()
                .is_some_and(|regex| regex.is_match(value)),
            MatchOperator::StartsWith => starts_with_ignore_ascii_case(value, &self.pattern),
            MatchOperator::EndsWith => ends_with_ignore_ascii_case(value, &self.pattern),
        }
    }
}

fn case_insensitive_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut builder = RegexBuilder::new(pattern);
    builder.case_insensitive(true).build()
}

fn contains_ignore_ascii_case(value: &str, pattern: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&pattern.to_ascii_lowercase())
}

fn starts_with_ignore_ascii_case(value: &str, pattern: &str) -> bool {
    value
        .get(..pattern.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(pattern))
}

fn ends_with_ignore_ascii_case(value: &str, pattern: &str) -> bool {
    value
        .get(value.len().saturating_sub(pattern.len())..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(pattern))
}
