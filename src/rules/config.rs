//! # `rules::config`
//!
//! **Purpose**: Typed traffic-control rules config module root.
//! **Public API**: `RulesConfig`, `HostsRuleConfig`, `ReplaceRuleConfig`,
//!   `DecodedReplaceRuleConfig`, `ReplacementRuleKind`, `RuleValueEncoding`, `RuleConfigError`
//! **Dependencies**: `rules::config::hosts`, `rules::config::replace`, `rules::config::value`,
//!   `rules::hosts`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 59 / 80

mod hosts;
mod replace;
#[cfg(test)]
mod tests;
mod value;

pub use hosts::HostsRuleConfig;
pub use replace::{DecodedReplaceRuleConfig, ReplaceRuleConfig, ReplacementRuleKind};
use serde::Deserialize;
pub use value::{RuleConfigError, RuleValueEncoding};

use crate::rules::hosts::{HostsRule, HostsRuleError};

/// Top-level traffic-control rules config.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    /// Ordered replacement rules.
    #[serde(default)]
    pub replace_rules: Vec<ReplaceRuleConfig>,
    /// Ordered host rewrite rules.
    #[serde(default)]
    pub hosts_rules: Vec<HostsRuleConfig>,
}

impl RulesConfig {
    /// Decodes configured replacement rules.
    ///
    /// # Returns
    /// Ordered decoded replacement rule configs.
    ///
    /// # Errors
    /// Returns `RuleConfigError` if any encoded `source` or `target` value is invalid.
    pub fn decode_replace_rules(&self) -> Result<Vec<DecodedReplaceRuleConfig>, RuleConfigError> {
        self.replace_rules
            .iter()
            .map(ReplaceRuleConfig::decode)
            .collect()
    }

    /// Builds configured host rewrite rules.
    ///
    /// # Returns
    /// Ordered compiled host rewrite rules.
    ///
    /// # Errors
    /// Returns `HostsRuleError` if any configured regex pattern is invalid.
    pub fn build_hosts_rules(&self) -> Result<Vec<HostsRule>, HostsRuleError> {
        self.hosts_rules
            .iter()
            .map(HostsRuleConfig::build)
            .collect()
    }
}
