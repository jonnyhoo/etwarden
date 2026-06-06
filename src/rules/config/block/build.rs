//! # `rules::config::block::build`
//!
//! **Purpose**: Builders for HTTP/WebSocket block-rule config collections.
//! **Public API**: `RulesConfig` HTTP/WebSocket block build methods
//! **Dependencies**: `rules::config::block`, `rules::block`, `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 48 / 80

use super::{HttpBlockRuleConfig, WebSocketBlockRuleConfig};
use crate::rules::{
    block::{http::HttpBlockRule, websocket::WebSocketBlockRule},
    config::RulesConfig,
    matcher::MatchError,
};

impl RulesConfig {
    /// Builds configured HTTP block rules.
    ///
    /// # Returns
    /// Ordered compiled HTTP block rules.
    ///
    /// # Errors
    /// Returns `MatchError` if any configured URL matcher pattern is invalid.
    pub fn build_http_block_rules(&self) -> Result<Vec<HttpBlockRule>, MatchError> {
        self.block_rules
            .http
            .iter()
            .map(HttpBlockRuleConfig::build)
            .collect()
    }

    /// Builds configured WebSocket block rules.
    ///
    /// # Returns
    /// Ordered compiled WebSocket block rules.
    ///
    /// # Errors
    /// Returns `MatchError` if any configured URL matcher pattern is invalid.
    pub fn build_websocket_block_rules(&self) -> Result<Vec<WebSocketBlockRule>, MatchError> {
        self.block_rules
            .websocket
            .iter()
            .map(WebSocketBlockRuleConfig::build)
            .collect()
    }
}
