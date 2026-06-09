//! # `process`
//!
//! **Purpose**: Subprocess spawn, lifecycle monitoring, and PID→process metadata resolution.
//! **Public API**: `struct SpawnResult`, `struct SpawnOptions`, `struct ProcessNameCache`,
//!   `struct ProcessTreeCache`, `struct TcpOwnerConnections`, `struct SpawnCaptureTarget`,
//!   `struct ProcessEntry`, `struct ProcessFilter`, `struct KillProcessResult`, `struct JobObject`,
//!   `fn spawn_and_get_pid`, `fn spawn_and_get_pid_with_options`, `fn snapshot_processes`,
//!   `fn filtered_processes`, `fn process_tree`, `fn kill_process`,
//!   `fn current_tcp_connections_for_pid`, `fn current_tcp_owners_with_connections`,
//!   `fn resolve_spawn_capture_target`
//! **Dependencies**: `error`, `sysinfo`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 36 / 80

pub mod inventory;
pub mod job;
pub mod kill;
pub mod lookup;
pub mod monitor;
pub mod network;
pub mod spawn;
pub mod spawn_capture;
pub mod tree;

pub use inventory::{
    filtered_processes, process_tree, snapshot_processes, ProcessEntry, ProcessFilter,
};
pub use job::JobObject;
pub use kill::{kill_process, KillProcessResult};
pub use lookup::ProcessNameCache;
pub use monitor::ProcessMonitor;
pub use network::{
    current_tcp_connections_for_pid, current_tcp_owners_with_connections, TcpOwnerConnections,
};
pub use spawn::{spawn_and_get_pid, spawn_and_get_pid_with_options, SpawnOptions, SpawnResult};
pub use spawn_capture::{resolve_spawn_capture_target, SpawnCaptureTarget};
pub use tree::{ProcessInfo, ProcessTreeCache};
