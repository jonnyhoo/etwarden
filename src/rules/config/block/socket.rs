//! # `rules::config::block::socket`
//!
//! **Purpose**: TCP/UDP socket block-rule config shapes and builders.
//! **Public API**: `SocketBlockRuleConfig`
//! **Dependencies**: `rules::block::socket`, `rules::config::block::socket::build`,
//!   `rules::matcher`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 63 / 80

mod build;
#[cfg(test)]
mod tests;

use serde::Deserialize;

use crate::rules::{
    block::socket::{SocketBlockAction, SocketBlockRule, SocketProtocol},
    matcher::{MatchError, MatchOperator},
};

/// Config shape for one TCP or UDP socket block rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SocketBlockRuleConfig {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Lower values win when multiple rules match.
    pub priority: u32,
    /// Address matching operation.
    #[serde(default = "default_address_operator")]
    pub address_operator: MatchOperator,
    /// Address pattern used by `address_operator`.
    #[serde(alias = "address")]
    pub address_pattern: String,
    /// Action emitted on match.
    pub action: SocketBlockAction,
}

impl SocketBlockRuleConfig {
    /// Builds one socket block rule for a configured protocol group.
    ///
    /// # Returns
    /// A compiled socket block rule.
    ///
    /// # Errors
    /// Returns `MatchError` when the configured address matcher pattern cannot compile.
    pub fn build(&self, protocol: SocketProtocol) -> Result<SocketBlockRule, MatchError> {
        SocketBlockRule::new(
            self.enable,
            self.priority,
            protocol,
            self.address_operator,
            &self.address_pattern,
            self.action,
        )
    }
}

const fn default_address_operator() -> MatchOperator {
    MatchOperator::Regex
}
