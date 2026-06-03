//! # `process`
//!
//! **Purpose**: Subprocess spawn, lifecycle monitoring, and PID→name resolution.
//! **Public API**: `struct SpawnResult`, `fn spawn_and_get_pid`, `struct ProcessNameCache`
//! **Dependencies**: `error`, `sysinfo`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 20 / 60

pub mod lookup;
pub mod monitor;
pub mod spawn;

pub use lookup::ProcessNameCache;
pub use monitor::ProcessMonitor;
pub use spawn::{spawn_and_get_pid, SpawnResult};
