//! # `rules::config::intercept`
//!
//! **Purpose**: Intercept-rule config shapes and builders.
//! **Public API**: `InterceptRuleConfig`
//! **Dependencies**: `rules::{intercept, matcher}`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 69 / 100

#[cfg(test)]
mod tests;

use serde::Deserialize;

use crate::rules::{
    intercept::{InterceptAction, InterceptDirection, InterceptRule, InterceptTarget},
    matcher::{MatchError, MatchOperator},
};

/// Config shape for one intercept rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InterceptRuleConfig {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Human-readable rule name.
    #[serde(default)]
    pub name: String,
    /// Direction constraint.
    pub direction: InterceptDirection,
    /// Context field to match.
    pub target: InterceptTarget,
    /// Text matching operation.
    pub operator: MatchOperator,
    /// Pattern value used by `operator`.
    pub value: String,
    /// Action emitted on match.
    pub action: InterceptAction,
    /// Human-readable note.
    #[serde(default)]
    pub note: String,
}

impl InterceptRuleConfig {
    /// Builds one intercept rule.
    ///
    /// # Returns
    /// A compiled intercept rule.
    ///
    /// # Errors
    /// Returns `MatchError` when a regex matcher pattern cannot compile.
    pub fn build(&self) -> Result<InterceptRule, MatchError> {
        InterceptRule::new(
            self.enable,
            &self.name,
            self.direction,
            self.target,
            self.operator,
            &self.value,
            self.action,
            &self.note,
        )
    }
}
