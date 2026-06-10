//! # `rules::block::socket`
//!
//! **Purpose**: Pure TCP/UDP socket block-rule matching by protocol, address, and priority.
//! **Public API**: `SocketBlockAction`, `SocketBlockContext`, `SocketBlockDecision`,
//!   `SocketBlockRule`, `SocketProtocol`, `evaluate_socket_first`
//! **Dependencies**: `rules::matcher`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 161 / 170

#[cfg(test)]
mod tests;

use crate::rules::matcher::{MatchError, MatchOperator, TextMatcher};

/// Socket transport protocol.
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum SocketProtocol {
    /// TCP socket traffic.
    Tcp,
    /// UDP socket traffic.
    Udp,
}

/// Action requested by a matching socket block rule.
#[derive(Debug, Clone, Copy, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum SocketBlockAction {
    /// Disconnect the matching socket flow.
    #[serde(alias = "断开连接")]
    Disconnect,
    /// Drop outbound payloads or packets.
    #[serde(alias = "丢弃上行")]
    DropUpstream,
    /// Drop inbound payloads or packets.
    #[serde(alias = "丢弃下行")]
    DropDownstream,
}

/// Runtime socket fields used by block-rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketBlockContext<'a> {
    /// Observed socket protocol.
    pub protocol: SocketProtocol,
    /// Remote address, usually `host:port` or `[ipv6]:port`.
    pub address: &'a str,
}

/// Ordered socket block rule with a precompiled address matcher.
#[derive(Debug, Clone)]
pub struct SocketBlockRule {
    /// Whether this rule participates in evaluation.
    pub enable: bool,
    /// Lower values win when multiple rules match.
    pub priority: u32,
    /// Socket protocol to match.
    pub protocol: SocketProtocol,
    /// Address matching operation.
    pub address_operator: MatchOperator,
    /// Address pattern used by `address_operator`.
    pub address_pattern: String,
    /// Action emitted on match.
    pub action: SocketBlockAction,
    address_matcher: TextMatcher,
}

/// Result of evaluating socket block rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketBlockDecision {
    /// No rule matched.
    Allow,
    /// A rule matched and requested a block action.
    Block {
        /// Index of the selected rule in the evaluated slice.
        rule_index: usize,
        /// Priority of the selected rule.
        priority: u32,
        /// Requested block action.
        action: SocketBlockAction,
    },
}

impl SocketBlockRule {
    /// Builds a socket block rule and precompiles its address matcher.
    ///
    /// # Arguments
    /// * `enable` — Whether this rule participates in evaluation.
    /// * `priority` — Lower values win when multiple rules match.
    /// * `protocol` — Socket protocol to match.
    /// * `address_operator` — Address matching operation.
    /// * `address_pattern` — Address pattern used by `address_operator`.
    /// * `action` — Action emitted on match.
    ///
    /// # Returns
    /// A rule with a precompiled address matcher.
    ///
    /// # Errors
    /// Returns `MatchError` when `address_operator` is regex and `address_pattern` cannot compile.
    pub fn new(
        enable: bool,
        priority: u32,
        protocol: SocketProtocol,
        address_operator: MatchOperator,
        address_pattern: impl Into<String>,
        action: SocketBlockAction,
    ) -> Result<Self, MatchError> {
        let address_pattern = address_pattern.into();
        Ok(Self {
            enable,
            priority,
            protocol,
            address_operator,
            address_matcher: TextMatcher::new(address_operator, address_pattern.clone())?,
            address_pattern,
            action,
        })
    }

    /// Checks whether this rule matches the supplied socket context.
    ///
    /// # Arguments
    /// * `context` — Socket protocol and address fields.
    ///
    /// # Returns
    /// `true` when the rule is enabled and protocol and address both match.
    #[must_use]
    pub fn matches(&self, context: &SocketBlockContext<'_>) -> bool {
        self.enable
            && self.protocol == context.protocol
            && self.address_matcher.matches(context.address)
    }
}

/// Evaluates rules and returns the highest-priority socket block decision.
///
/// # Arguments
/// * `context` — Socket protocol and address fields.
/// * `rules` — Socket block rules. Lower `priority` wins; ties keep earlier rule order.
///
/// # Returns
/// `SocketBlockDecision::Block` for the selected matching rule; otherwise `Allow`.
#[must_use]
pub fn evaluate_socket_first(
    context: &SocketBlockContext<'_>,
    rules: &[SocketBlockRule],
) -> SocketBlockDecision {
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.matches(context))
        .min_by_key(|(rule_index, rule)| (rule.priority, *rule_index))
        .map_or(SocketBlockDecision::Allow, |(rule_index, rule)| {
            SocketBlockDecision::Block {
                rule_index,
                priority: rule.priority,
                action: rule.action,
            }
        })
}
