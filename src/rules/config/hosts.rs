//! # `rules::config::hosts`
//!
//! **Purpose**: Host-rewrite config shapes and builders.
//! **Public API**: `HostsRuleConfig`
//! **Dependencies**: `rules::hosts`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 39 / 80

#[cfg(test)]
mod tests;

use serde::Deserialize;

use crate::rules::hosts::{HostsRule, HostsRuleError};

/// Config shape for one host rewrite rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HostsRuleConfig {
    /// Case-insensitive regex matched against URL hosts.
    pub pattern: String,
    /// Replacement host. Regex captures are supported.
    pub target: String,
}

impl HostsRuleConfig {
    /// Builds one host rewrite rule.
    ///
    /// # Returns
    /// A compiled host rewrite rule.
    ///
    /// # Errors
    /// Returns `HostsRuleError` when `pattern` cannot compile.
    pub fn build(&self) -> Result<HostsRule, HostsRuleError> {
        HostsRule::new(&self.pattern, &self.target)
    }
}
