//! # `rules::config::block::http`
//!
//! **Purpose**: HTTP block-rule config shapes and builders.
//! **Public API**: `HttpBlockRuleConfig`
//! **Dependencies**: `rules::block::http`, `rules::matcher`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 61 / 80

#[cfg(test)]
mod tests;

use serde::Deserialize;

use crate::rules::{
    block::http::{HttpBlockAction, HttpBlockRule},
    matcher::{MatchError, MatchOperator},
};

/// Config shape for one HTTP block rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HttpBlockRuleConfig {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Lower values win when multiple rules match.
    pub priority: u32,
    /// HTTP method to match, or `*` for any method.
    pub method: String,
    /// URL matching operation.
    #[serde(default = "default_url_operator", alias = "url_match_type")]
    pub url_operator: MatchOperator,
    /// URL pattern used by `url_operator`.
    pub url_pattern: String,
    /// Action emitted on match.
    pub action: HttpBlockAction,
}

impl HttpBlockRuleConfig {
    /// Builds one HTTP block rule.
    ///
    /// # Returns
    /// A compiled HTTP block rule.
    ///
    /// # Errors
    /// Returns `MatchError` when the configured URL matcher pattern cannot compile.
    pub fn build(&self) -> Result<HttpBlockRule, MatchError> {
        HttpBlockRule::new(
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
