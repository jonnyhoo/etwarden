//! # `process`
//!
//! **Purpose**: Subprocess spawn, lifecycle monitoring, and PID→process metadata resolution.
//! **Public API**: `struct SpawnResult`, `struct ProcessNameCache`, `struct ProcessTreeCache`,
//!   `struct TcpOwnerConnections`, `struct SpawnCaptureTarget`, `fn spawn_and_get_pid`,
//!   `fn current_tcp_connections_for_pid`, `fn current_tcp_owners_with_connections`,
//!   `fn resolve_spawn_capture_target`
//! **Dependencies**: `error`, `sysinfo`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 27 / 60

pub mod lookup;
pub mod monitor;
pub mod network;
pub mod spawn;
pub mod spawn_capture;
pub mod tree;

pub use lookup::ProcessNameCache;
pub use monitor::ProcessMonitor;
pub use network::{
    current_tcp_connections_for_pid, current_tcp_owners_with_connections, TcpOwnerConnections,
};
pub use spawn::{spawn_and_get_pid, SpawnResult};
pub use spawn_capture::{resolve_spawn_capture_target, SpawnCaptureTarget};
pub use tree::{ProcessInfo, ProcessTreeCache};
