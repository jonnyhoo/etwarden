//! # `rules::config::block::websocket`
//!
//! **Purpose**: WebSocket block-rule config shapes and builders.
//! **Public API**: `WebSocketBlockRuleConfig`
//! **Dependencies**: `rules::block::websocket`, `rules::matcher`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 56 / 80

#[cfg(test)]
mod tests;

use serde::Deserialize;

use crate::rules::{
    block::websocket::{WebSocketBlockAction, WebSocketBlockRule},
    matcher::{MatchError, MatchOperator},
};

/// Config shape for one WebSocket block rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WebSocketBlockRuleConfig {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Lower values win when multiple rules match.
    pub priority: u32,
    /// HTTP upgrade method to match, or `*` for any method.
    pub method: String,
    /// URL matching operation.
    #[serde(default = "default_url_operator")]
    pub url_operator: MatchOperator,
    /// URL pattern used by `url_operator`.
    pub url_pattern: String,
    /// Action emitted on match.
    pub action: WebSocketBlockAction,
}

impl WebSocketBlockRuleConfig {
    /// Builds one WebSocket block rule.
    ///
    /// # Returns
    /// A compiled WebSocket block rule.
    ///
    /// # Errors
    /// Returns `MatchError` when the configured URL matcher pattern cannot compile.
    pub fn build(&self) -> Result<WebSocketBlockRule, MatchError> {
        WebSocketBlockRule::new(
            self.enable,
            self.priority,
            &self.method,
            self.url_operator,
            &self.url_pattern,
            self.action,
        )
    }
}

const fn default_url_operator() -> MatchOperator {
    MatchOperator::Regex
}
