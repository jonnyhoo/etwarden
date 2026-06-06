//! # `rules::block`
//!
//! **Purpose**: Traffic block-rule evaluators.
//! **Public API**: `http`, `websocket`
//! **Dependencies**: `rules::block::http`, `rules::block::websocket`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 15 / 80

pub mod http;
pub mod websocket;

pub(super) fn method_matches(rule_method: &str, observed: &str) -> bool {
    rule_method == "*" || rule_method.eq_ignore_ascii_case(observed)
}
