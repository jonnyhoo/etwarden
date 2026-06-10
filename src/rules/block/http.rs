//! # `rules::block::http`
//!
//! **Purpose**: Pure HTTP block-rule matching by method, URL, and priority.
//! **Public API**: `HttpBlockAction`, `HttpBlockContext`, `HttpBlockDecision`,
//!   `HttpBlockRule`, `evaluate_http_first`
//! **Dependencies**: `rules::matcher`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 149 / 160

#[cfg(test)]
mod tests;

use super::method_matches;
use crate::rules::matcher::{MatchError, MatchOperator, TextMatcher};

/// Action requested by a matching HTTP block rule.
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum HttpBlockAction {
    /// Close the request before forwarding upstream.
    #[serde(alias = "断开请求")]
    CloseRequest,
    /// Close the response before forwarding downstream.
    #[serde(alias = "断开响应")]
    CloseResponse,
}

/// Runtime HTTP fields used by block-rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpBlockContext<'a> {
    /// HTTP method, for example `GET` or `POST`.
    pub method: &'a str,
    /// Full request URL or URL-like target.
    pub url: &'a str,
}

/// Ordered HTTP block rule with a precompiled URL matcher.
#[derive(Debug, Clone)]
pub struct HttpBlockRule {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Lower values win when multiple rules match.
    pub priority: u32,
    /// HTTP method to match, or `*` for any method.
    pub method: String,
    /// URL matching operation.
    pub url_operator: MatchOperator,
    /// URL pattern used by `url_operator`.
    pub url_pattern: String,
    /// Action emitted on match.
    pub action: HttpBlockAction,
    url_matcher: TextMatcher,
}

/// Result of evaluating HTTP block rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBlockDecision {
    /// No rule matched.
    Allow,
    /// A rule matched and requested a block action.
    Block {
        /// Index of the selected rule in the evaluated slice.
        rule_index: usize,
        /// Priority of the selected rule.
        priority: u32,
        /// Requested block action.
        action: HttpBlockAction,
    },
}

impl HttpBlockRule {
    /// Builds an HTTP block rule and precompiles its URL matcher.
    ///
    /// # Arguments
    /// * `enable` — Whether this rule participates in evaluation.
    /// * `priority` — Lower values win when multiple rules match.
    /// * `method` — HTTP method to match, or `*` for any method.
    /// * `url_operator` — URL matching operation.
    /// * `url_pattern` — URL pattern used by `url_operator`.
    /// * `action` — Action emitted on match.
    ///
    /// # Returns
    /// A rule with a precompiled URL matcher.
    ///
    /// # Errors
    /// Returns `MatchError` when `url_operator` is regex and `url_pattern` cannot compile.
    pub fn new(
        enable: bool,
        priority: u32,
        method: impl Into<String>,
        url_operator: MatchOperator,
        url_pattern: impl Into<String>,
        action: HttpBlockAction,
    ) -> Result<Self, MatchError> {
        let url_pattern = url_pattern.into();
        Ok(Self {
            enable,
            priority,
            method: method.into(),
            url_operator,
            url_matcher: TextMatcher::new(url_operator, url_pattern.clone())?,
            url_pattern,
            action,
        })
    }

    /// Checks whether this rule matches the supplied HTTP context.
    ///
    /// # Arguments
    /// * `context` — HTTP method and URL fields.
    ///
    /// # Returns
    /// `true` when the rule is enabled and method and URL both match.
    #[must_use]
    pub fn matches(&self, context: &HttpBlockContext<'_>) -> bool {
        self.enable
            && method_matches(&self.method, context.method)
            && self.url_matcher.matches(context.url)
    }
}

/// Evaluates rules and returns the highest-priority HTTP block decision.
///
/// # Arguments
/// * `context` — HTTP method and URL fields.
/// * `rules` — HTTP block rules. Lower `priority` wins; ties keep earlier rule order.
///
/// # Returns
/// `HttpBlockDecision::Block` for the selected matching rule; otherwise `Allow`.
#[must_use]
pub fn evaluate_http_first(
    context: &HttpBlockContext<'_>,
    rules: &[HttpBlockRule],
) -> HttpBlockDecision {
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.matches(context))
        .min_by_key(|(rule_index, rule)| (rule.priority, *rule_index))
        .map_or(HttpBlockDecision::Allow, |(rule_index, rule)| {
            HttpBlockDecision::Block {
                rule_index,
                priority: rule.priority,
                action: rule.action,
            }
        })
}
