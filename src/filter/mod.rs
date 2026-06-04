//! # `filter`
//!
//! **Purpose**: Event filtering — drop/allow per `NetEvent`.
//! **Public API**: `trait Filter`, `mod pid`, `mod tree`
//! **Dependencies**: `parser`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 25 / 60

pub mod pid;
pub mod tree;

use crate::parser::types::NetEvent;

/// Decides whether a `NetEvent` should be passed downstream or dropped.
pub trait Filter: Send + Sync {
    /// Returns `true` if the event should be allowed through.
    ///
    /// # Arguments
    /// * `event` — The network event to evaluate.
    ///
    /// # Returns
    /// `true` to allow, `false` to drop.
    fn allow(&self, event: &NetEvent) -> bool;
}
