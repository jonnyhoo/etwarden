//! # `rules`
//!
//! **Purpose**: Traffic-control rule engine modules.
//! **Public API**: `pub mod config`, `pub mod matcher`, `pub mod replace`
//! **Dependencies**: `rules::config`, `rules::matcher`, `rules::replace`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 11 / 80

pub mod config;
pub mod matcher;
pub mod replace;
