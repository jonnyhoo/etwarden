//! # `rules::intercept`
//!
//! **Purpose**: Pure intercept-rule evaluation for traffic-control decisions.
//! **Public API**: `InterceptAction`, `InterceptContext`, `InterceptDecision`,
//!   `InterceptDirection`, `InterceptRule`, `InterceptTarget`, `evaluate_first`
//! **Dependencies**: `rules::intercept::rule`, `rules::intercept::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 19 / 80

mod rule;
#[cfg(test)]
mod tests;
mod types;

pub use rule::{evaluate_first, InterceptRule};
pub use types::{
    InterceptAction, InterceptContext, InterceptDecision, InterceptDirection, InterceptTarget,
};
