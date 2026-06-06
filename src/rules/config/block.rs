//! # `rules::config::block`
//!
//! **Purpose**: Block-rule config group shape.
//! **Public API**: `BlockRulesConfig`, `HttpBlockRuleConfig`, `WebSocketBlockRuleConfig`
//! **Dependencies**: `rules::config::block::{build, http, websocket}`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 32 / 80

mod build;
mod http;
mod websocket;

pub use http::HttpBlockRuleConfig;
use serde::Deserialize;
pub use websocket::WebSocketBlockRuleConfig;

/// Config shape for grouped block rules.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct BlockRulesConfig {
    /// Ordered HTTP block rules.
    #[serde(default)]
    pub http: Vec<HttpBlockRuleConfig>,
    /// Ordered WebSocket block rules.
    #[serde(default)]
    pub websocket: Vec<WebSocketBlockRuleConfig>,
}
