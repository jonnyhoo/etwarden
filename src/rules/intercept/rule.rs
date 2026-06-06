//! # `rules::intercept::rule`
//!
//! **Purpose**: Intercept rule construction and ordered evaluation.
//! **Public API**: `InterceptRule`, `evaluate_first`
//! **Dependencies**: `rules::intercept::types`, `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 137 / 160

use std::borrow::Cow;

use super::types::{
    InterceptAction, InterceptContext, InterceptDecision, InterceptDirection, InterceptTarget,
};
use crate::rules::matcher::{MatchError, MatchOperator, TextMatcher};

/// Ordered intercept rule with precompiled text matcher.
#[derive(Debug, Clone)]
pub struct InterceptRule {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Human-readable rule name.
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
    pub note: String,
    matcher: TextMatcher,
}

impl InterceptRule {
    /// Builds an intercept rule and precompiles its matcher.
    ///
    /// # Arguments
    /// * `enable` — Whether this rule participates in evaluation.
    /// * `name` — Human-readable rule name.
    /// * `direction` — Direction constraint.
    /// * `target` — Context field to match.
    /// * `operator` — Text matching operation.
    /// * `value` — Pattern value used by `operator`.
    /// * `action` — Action emitted on match.
    /// * `note` — Human-readable note.
    ///
    /// # Returns
    /// A rule with a precompiled text matcher.
    ///
    /// # Errors
    /// Returns `MatchError` when `operator` is regex and `value` cannot compile.
    pub fn new(
        enable: bool,
        name: impl Into<String>,
        direction: InterceptDirection,
        target: InterceptTarget,
        operator: MatchOperator,
        value: impl Into<String>,
        action: InterceptAction,
        note: impl Into<String>,
    ) -> Result<Self, MatchError> {
        let value = value.into();
        Ok(Self {
            enable,
            name: name.into(),
            direction,
            target,
            operator,
            matcher: TextMatcher::new(operator, value.clone())?,
            value,
            action,
            note: note.into(),
        })
    }

    /// Checks whether this rule matches the supplied context.
    ///
    /// # Arguments
    /// * `context` — Text fields for the current traffic item.
    ///
    /// # Returns
    /// `true` when the rule is enabled, direction matches, target text exists, and matcher matches.
    #[must_use]
    pub fn matches(&self, context: &InterceptContext<'_>) -> bool {
        if !self.enable || !self.direction.matches(context.direction) {
            return false;
        }
        let Some(text) = target_text(self.target, context) else {
            return false;
        };
        self.matcher.matches(text.as_ref())
    }
}

/// Evaluates rules in order and returns the first intercept decision.
///
/// # Arguments
/// * `context` — Text fields for the current traffic item.
/// * `rules` — Ordered intercept rules.
///
/// # Returns
/// `InterceptDecision::Intercept` for the first matching rule; otherwise `Allow`.
#[must_use]
pub fn evaluate_first(
    context: &InterceptContext<'_>,
    rules: &[InterceptRule],
) -> InterceptDecision {
    rules
        .iter()
        .enumerate()
        .find_map(|(rule_index, rule)| {
            rule.matches(context)
                .then_some(InterceptDecision::Intercept {
                    rule_index,
                    action: rule.action,
                })
        })
        .unwrap_or(InterceptDecision::Allow)
}

fn target_text<'a>(
    target: InterceptTarget,
    context: &InterceptContext<'a>,
) -> Option<Cow<'a, str>> {
    match target {
        InterceptTarget::Url => context.url.map(Cow::Borrowed),
        InterceptTarget::Header => context.headers.map(Cow::Borrowed),
        InterceptTarget::Body => context.body.map(Cow::Borrowed),
        InterceptTarget::Pid => context.pid.map(|pid| Cow::Owned(pid.to_string())),
        InterceptTarget::ProcessName => context.process_name.map(Cow::Borrowed),
    }
}
