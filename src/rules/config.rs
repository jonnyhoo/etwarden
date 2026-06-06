//! # `rules::config`
//!
//! **Purpose**: Typed traffic-control rules config module root.
//! **Public API**: `RulesConfig`, `BlockRulesConfig`, `HostsRuleConfig`, `HttpBlockRuleConfig`,
//!   `InterceptRuleConfig`, `ReplaceRuleConfig`, `DecodedReplaceRuleConfig`,
//!   `ReplacementRuleKind`, `RuleValueEncoding`, `RuleConfigError`
//! **Dependencies**: `rules::config::{block, build, hosts, intercept, replace, value}`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 44 / 80

mod block;
mod build;
mod hosts;
mod intercept;
mod replace;
#[cfg(test)]
mod tests;
mod value;

pub use block::{BlockRulesConfig, HttpBlockRuleConfig};
pub use hosts::HostsRuleConfig;
pub use intercept::InterceptRuleConfig;
pub use replace::{DecodedReplaceRuleConfig, ReplaceRuleConfig, ReplacementRuleKind};
use serde::Deserialize;
pub use value::{RuleConfigError, RuleValueEncoding};

/// Top-level traffic-control rules config.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    /// Ordered replacement rules.
    #[serde(default)]
    pub replace_rules: Vec<ReplaceRuleConfig>,
    /// Ordered intercept rules.
    #[serde(default)]
    pub intercept_rules: Vec<InterceptRuleConfig>,
    /// Ordered host rewrite rules.
    #[serde(default)]
    pub hosts_rules: Vec<HostsRuleConfig>,
    /// Grouped block rules.
    #[serde(default)]
    pub block_rules: BlockRulesConfig,
}
