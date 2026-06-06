//! # `rules::config::build`
//!
//! **Purpose**: Builders for top-level rules config collections.
//! **Public API**: `RulesConfig` methods
//! **Dependencies**: `rules::config`, `rules::{hosts, intercept, matcher}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 80

use super::{
    DecodedReplaceRuleConfig, HostsRuleConfig, InterceptRuleConfig, ReplaceRuleConfig,
    RuleConfigError, RulesConfig,
};
use crate::rules::{
    hosts::{HostsRule, HostsRuleError},
    intercept::InterceptRule,
    matcher::MatchError,
};

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

    /// Builds configured intercept rules.
    ///
    /// # Returns
    /// Ordered compiled intercept rules.
    ///
    /// # Errors
    /// Returns `MatchError` if any configured matcher pattern is invalid.
    pub fn build_intercept_rules(&self) -> Result<Vec<InterceptRule>, MatchError> {
        self.intercept_rules
            .iter()
            .map(InterceptRuleConfig::build)
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
