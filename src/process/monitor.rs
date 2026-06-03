//! # `process::monitor`
//!
//! **Purpose**: Monitor a child process lifecycle (alive check, wait for exit).
//! **Public API**: `struct ProcessMonitor`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 120

use std::process::Child;

use crate::error::EtwardenError;

/// Monitors a child process for liveness and exit status.
///
/// Wraps a [`std::process::Child`] with query methods suitable for
/// capture-then-wait workflows.
pub struct ProcessMonitor {
    child: Child,
}

impl ProcessMonitor {
    /// Creates a new monitor from a spawned child process.
    ///
    /// # Arguments
    /// * `child` — The spawned child process to monitor.
    #[must_use]
    pub const fn new(child: Child) -> Self {
        Self { child }
    }

    /// Returns the PID of the monitored process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns true if the process is still running.
    pub fn is_alive(&mut self) -> bool {
        self.child.try_wait().is_ok_and(|status| status.is_none())
    }

    /// Blocks until the process exits, returning its exit code.
    ///
    /// # Errors
    /// Returns [`EtwardenError::ProcessSpawn`] if the wait fails.
    pub fn wait_exit(&mut self) -> Result<u32, EtwardenError> {
        let status = self
            .child
            .wait()
            .map_err(|e| EtwardenError::ProcessSpawn(format!("wait failed: {e}")))?;
        Ok(status.code().map_or(1, i32::cast_unsigned))
    }
}
