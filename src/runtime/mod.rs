//! # `runtime`
//!
//! **Purpose**: High-level browse subcommand runtime — browser discovery, CDP lifecycle, capture orchestration.
//! **Public API**: `pub mod browse`, `pub mod cdp`, `pub mod which`
//! **Dependencies**: (none — internal module root)
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 10 / 80

pub mod browse;
pub mod cdp;
pub mod which;
