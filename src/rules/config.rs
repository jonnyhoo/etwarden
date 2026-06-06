//! # `rules::config`
//!
//! **Purpose**: Typed traffic-control rules config module root.
//! **Public API**: `RulesConfig`, `HostsRuleConfig`, `InterceptRuleConfig`,
//!   `ReplaceRuleConfig`, `DecodedReplaceRuleConfig`, `ReplacementRuleKind`, `RuleValueEncoding`,
//!   `RuleConfigError`
//! **Dependencies**: `rules::config::build`, `rules::config::hosts`,
//!   `rules::config::intercept`, `rules::config::replace`, `rules::config::value`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 40 / 80

mod build;
mod hosts;
mod intercept;
mod replace;
#[cfg(test)]
mod tests;
mod value;

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
}
