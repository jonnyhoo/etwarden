//! # `rules::ruleset`
//!
//! **Purpose**: Compiled runtime rule set built from `RulesConfig`.
//! **Public API**: `RuleSet`, `RuleSetError`
//! **Dependencies**: `rules::{block, hosts, intercept, replace, config}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 89 / 120

#[cfg(test)]
mod tests;

use crate::rules::{
    block::{http::HttpBlockRule, socket::SocketBlockRule, websocket::WebSocketBlockRule},
    config::RulesConfig,
    hosts::HostsRule,
    intercept::InterceptRule,
    replace::ReplaceRule,
};

/// Compiled runtime error from building a `RuleSet`.
#[derive(Debug, thiserror::Error)]
pub enum RuleSetError {
    /// A replacement rule value encoding is invalid.
    #[error("replace rule config error: {0}")]
    ReplaceConfig(#[from] crate::rules::config::RuleConfigError),
    /// A regex or match pattern is invalid.
    #[error("match pattern error: {0}")]
    MatchPattern(#[from] crate::rules::matcher::MatchError),
    /// A hosts rule pattern is invalid.
    #[error("hosts rule error: {0}")]
    HostsPattern(#[from] crate::rules::hosts::HostsRuleError),
}

/// Compiled set of all traffic-control rules, ready for evaluation.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    /// Ordered URL/body byte-replacement rules.
    pub replace: Vec<ReplaceRule>,
    /// Ordered intercept/drop/disconnect rules.
    pub intercept: Vec<InterceptRule>,
    /// Ordered host-rewrite rules.
    pub hosts: Vec<HostsRule>,
    /// Ordered HTTP block rules.
    pub http_block: Vec<HttpBlockRule>,
    /// Ordered WebSocket block rules.
    pub websocket_block: Vec<WebSocketBlockRule>,
    /// Ordered TCP block rules.
    pub tcp_block: Vec<SocketBlockRule>,
    /// Ordered UDP block rules.
    pub udp_block: Vec<SocketBlockRule>,
}

impl RuleSet {
    /// Builds a `RuleSet` from a config, compiling all patterns.
    ///
    /// # Arguments
    /// * `config` — Parsed rules configuration.
    ///
    /// # Returns
    /// A fully compiled `RuleSet`.
    ///
    /// # Errors
    /// Returns `RuleSetError` if any pattern or encoding is invalid.
    pub fn build(config: &RulesConfig) -> Result<Self, RuleSetError> {
        Ok(Self {
            replace: config.build_replace_rules()?,
            intercept: config.build_intercept_rules()?,
            hosts: config.build_hosts_rules()?,
            http_block: config.build_http_block_rules()?,
            websocket_block: config.build_websocket_block_rules()?,
            tcp_block: config.build_tcp_block_rules()?,
            udp_block: config.build_udp_block_rules()?,
        })
    }

    /// Returns `true` when no rules are configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.replace.is_empty()
            && self.intercept.is_empty()
            && self.hosts.is_empty()
            && self.http_block.is_empty()
            && self.websocket_block.is_empty()
            && self.tcp_block.is_empty()
            && self.udp_block.is_empty()
    }
}
