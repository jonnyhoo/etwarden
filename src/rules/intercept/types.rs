//! # `rules::intercept::types`
//!
//! **Purpose**: Public data types for intercept-rule evaluation.
//! **Public API**: `InterceptAction`, `InterceptContext`, `InterceptDecision`,
//!   `InterceptDirection`, `InterceptTarget`
//! **Dependencies**: `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 99 / 120

/// Flow direction for intercept rule matching.
#[derive(Debug, Clone, Copy, Default, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
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
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum InterceptTarget {
    /// Full request URL.
    #[serde(alias = "URL")]
    Url,
    /// Concatenated request or response headers.
    Header,
    /// Text request or response body.
    Body,
    /// Process identifier rendered as decimal text.
    #[serde(alias = "PID")]
    Pid,
    /// Process executable name.
    ProcessName,
}

/// Action requested by a matching intercept rule.
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
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
