//! # `rules::block::websocket`
//!
//! **Purpose**: Pure WebSocket block-rule matching by method, URL, and priority.
//! **Public API**: `WebSocketBlockAction`, `WebSocketBlockContext`, `WebSocketBlockDecision`,
//!   `WebSocketBlockRule`, `evaluate_websocket_first`
//! **Dependencies**: `rules::block`, `rules::matcher`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 149 / 170

#[cfg(test)]
mod tests;

use super::method_matches;
use crate::rules::matcher::{MatchError, MatchOperator, TextMatcher};

/// Action requested by a matching WebSocket block rule.
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum WebSocketBlockAction {
    /// Close the WebSocket connection.
    CloseConnection,
    /// Drop a client-to-server frame.
    DropUpstreamFrame,
    /// Drop a server-to-client frame.
    DropDownstreamFrame,
}

/// Runtime WebSocket fields used by block-rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketBlockContext<'a> {
    /// HTTP upgrade method, normally `GET`.
    pub method: &'a str,
    /// Full request URL or URL-like target.
    pub url: &'a str,
}

/// Ordered WebSocket block rule with a precompiled URL matcher.
#[derive(Debug, Clone)]
pub struct WebSocketBlockRule {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Lower values win when multiple rules match.
    pub priority: u32,
    /// HTTP upgrade method to match, or `*` for any method.
    pub method: String,
    /// URL matching operation.
    pub url_operator: MatchOperator,
    /// URL pattern used by `url_operator`.
    pub url_pattern: String,
    /// Action emitted on match.
    pub action: WebSocketBlockAction,
    url_matcher: TextMatcher,
}

/// Result of evaluating WebSocket block rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketBlockDecision {
    /// No rule matched.
    Allow,
    /// A rule matched and requested a block action.
    Block {
        /// Index of the selected rule in the evaluated slice.
        rule_index: usize,
        /// Priority of the selected rule.
        priority: u32,
        /// Requested block action.
        action: WebSocketBlockAction,
    },
}

impl WebSocketBlockRule {
    /// Builds a WebSocket block rule and precompiles its URL matcher.
    ///
    /// # Arguments
    /// * `enable` — Whether this rule participates in evaluation.
    /// * `priority` — Lower values win when multiple rules match.
    /// * `method` — HTTP upgrade method to match, or `*` for any method.
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
        action: WebSocketBlockAction,
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

    /// Checks whether this rule matches the supplied WebSocket context.
    ///
    /// # Arguments
    /// * `context` — HTTP upgrade method and URL fields.
    ///
    /// # Returns
    /// `true` when the rule is enabled and method and URL both match.
    #[must_use]
    pub fn matches(&self, context: &WebSocketBlockContext<'_>) -> bool {
        self.enable
            && method_matches(&self.method, context.method)
            && self.url_matcher.matches(context.url)
    }
}

/// Evaluates rules and returns the highest-priority WebSocket block decision.
///
/// # Arguments
/// * `context` — HTTP upgrade method and URL fields.
/// * `rules` — WebSocket block rules. Lower `priority` wins; ties keep earlier rule order.
///
/// # Returns
/// `WebSocketBlockDecision::Block` for the selected matching rule; otherwise `Allow`.
#[must_use]
pub fn evaluate_websocket_first(
    context: &WebSocketBlockContext<'_>,
    rules: &[WebSocketBlockRule],
) -> WebSocketBlockDecision {
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.matches(context))
        .min_by_key(|(rule_index, rule)| (rule.priority, *rule_index))
        .map_or(WebSocketBlockDecision::Allow, |(rule_index, rule)| {
            WebSocketBlockDecision::Block {
                rule_index,
                priority: rule.priority,
                action: rule.action,
            }
        })
}
