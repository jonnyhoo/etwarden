//! # `process`
//!
//! **Purpose**: Subprocess spawn and lifecycle monitoring.
//! **Public API**: `struct SpawnResult`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 22 / 60

use crate::error::EtwardenError;

/// Result of spawning a child process via `--spawn` mode.
pub struct SpawnResult {
    /// The process ID of the spawned child.
    pub pid: u32,
}

/// Spawns a child process and returns its PID.
///
/// # Arguments
/// * `_cmd` — The command string to execute.
///
/// # Returns
/// A `SpawnResult` containing the child PID.
///
/// # Errors
/// Returns [`EtwardenError::ProcessSpawn`] if the spawn fails.
pub fn spawn_and_get_pid(_cmd: &str) -> std::result::Result<SpawnResult, EtwardenError> {
    // T29 will implement
    Err(EtwardenError::ProcessSpawn("not implemented".into()))
}
