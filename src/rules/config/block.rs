//! # `rules::config::block`
//!
//! **Purpose**: Block-rule config group shape.
//! **Public API**: `BlockRulesConfig`, `HttpBlockRuleConfig`
//! **Dependencies**: `rules::config::block::http`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 26 / 80

mod http;

pub use http::HttpBlockRuleConfig;
use serde::Deserialize;

/// Config shape for grouped block rules.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct BlockRulesConfig {
    /// Ordered HTTP block rules.
    #[serde(default)]
    pub http: Vec<HttpBlockRuleConfig>,
}
