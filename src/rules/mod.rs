//! # `rules`
//!
//! **Purpose**: Traffic-control rule engine modules.
//! **Public API**: `pub mod config`, `pub mod hosts`, `pub mod intercept`, `pub mod matcher`,
//!   `pub mod replace`
//! **Dependencies**: `rules::config`, `rules::hosts`, `rules::intercept`, `rules::matcher`,
//!   `rules::replace`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 16 / 80

pub mod config;
pub mod hosts;
pub mod intercept;
pub mod matcher;
pub mod replace;
