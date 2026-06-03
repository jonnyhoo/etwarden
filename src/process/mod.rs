//! # `process`
//!
//! **Purpose**: Subprocess spawn and lifecycle monitoring.
//! **Public API**: `struct SpawnResult`, `fn spawn_and_get_pid`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 16 / 60

pub mod monitor;
pub mod spawn;

pub use monitor::ProcessMonitor;
pub use spawn::{spawn_and_get_pid, SpawnResult};
