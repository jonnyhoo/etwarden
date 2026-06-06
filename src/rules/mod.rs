//! # `rules`
//!
//! **Purpose**: Traffic-control rule engine modules.
//! **Public API**: `pub mod block`, `pub mod config`, `pub mod hosts`, `pub mod intercept`,
//!   `pub mod matcher`, `pub mod replace`, `pub mod ruleset`
//! **Dependencies**: `rules::block`, `rules::config`, `rules::hosts`, `rules::intercept`,
//!   `rules::matcher`, `rules::replace`, `rules::ruleset`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 19 / 80

pub mod block;
pub mod config;
pub mod hosts;
pub mod intercept;
pub mod matcher;
pub mod replace;
pub mod ruleset;
