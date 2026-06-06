//! # `rules::intercept`
//!
//! **Purpose**: Pure intercept-rule evaluation for traffic-control decisions.
//! **Public API**: `InterceptAction`, `InterceptContext`, `InterceptDecision`,
//!   `InterceptDirection`, `InterceptRule`, `InterceptTarget`, `evaluate_first`
//! **Dependencies**: `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 164 / 180

#[cfg(test)]
mod tests;

use std::borrow::Cow;

use crate::rules::matcher::{MatchError, MatchOperator, TextMatcher};

/// Flow direction for intercept rule matching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InterceptDirection {
    /// Client-to-server traffic.
    Upstream,
    /// Server-to-client traffic.
    Downstream,
    /// Either direction.
    #[default]
    Both,
}

/// Text source used by an intercept rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptTarget {
    /// Full request URL.
    Url,
    /// Concatenated request or response headers.
    Header,
    /// Text request or response body.
    Body,
    /// Process identifier rendered as decimal text.
    Pid,
    /// Process executable name.
    ProcessName,
}

/// Action requested by a matching intercept rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptAction {
    /// Drop the matching payload or frame.
    Drop,
    /// Disconnect the matching flow.
    Disconnect,
    /// Pause processing for debugger/UI intervention.
    Pause,
}

/// Runtime text fields available to intercept-rule evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterceptContext<'a> {
    /// Direction of the current traffic item.
    pub direction: InterceptDirection,
    /// Full request URL when available.
    pub url: Option<&'a str>,
    /// Concatenated headers when available.
    pub headers: Option<&'a str>,
    /// Text body when available.
    pub body: Option<&'a str>,
    /// Process identifier when available.
    pub pid: Option<u32>,
    /// Process executable name when available.
    pub process_name: Option<&'a str>,
}

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

/// Result of evaluating intercept rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDecision {
    /// No rule matched.
    Allow,
    /// A rule matched and requested an intercept action.
    Intercept {
        /// Index of the matching rule in the evaluated slice.
        rule_index: usize,
        /// Requested intercept action.
        action: InterceptAction,
    },
}

impl InterceptDirection {
    /// Checks whether a rule direction matches an observed traffic direction.
    ///
    /// # Returns
    /// `true` when either side is `Both` or both concrete directions are equal.
    #[must_use]
    pub const fn matches(self, observed: Self) -> bool {
        matches!(
            (self, observed),
            (Self::Both, _)
                | (_, Self::Both)
                | (Self::Upstream, Self::Upstream)
                | (Self::Downstream, Self::Downstream)
        )
    }
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
