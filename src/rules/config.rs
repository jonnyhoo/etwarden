//! # `rules::config`
//!
//! **Purpose**: Typed traffic-control rules config module root.
//! **Public API**: `RulesConfig`, `ReplaceRuleConfig`, `DecodedReplaceRuleConfig`,
//!   `ReplacementRuleKind`, `RuleValueEncoding`, `RuleConfigError`
//! **Dependencies**: `rules::config::replace`, `rules::config::value`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 42 / 80

mod replace;
#[cfg(test)]
mod tests;
mod value;

pub use replace::{DecodedReplaceRuleConfig, ReplaceRuleConfig, ReplacementRuleKind};
use serde::Deserialize;
pub use value::{RuleConfigError, RuleValueEncoding};

/// Top-level traffic-control rules config.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    /// Ordered replacement rules.
    #[serde(default)]
    pub replace_rules: Vec<ReplaceRuleConfig>,
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
}
