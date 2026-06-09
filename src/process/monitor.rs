//! # `process::monitor`
//!
//! **Purpose**: Monitor a child process lifecycle (alive check, wait for exit).
//! **Public API**: `struct ProcessMonitor`
//! **Dependencies**: `error`, `process::job`, `windows`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 75 / 120

#![expect(unsafe_code, reason = "Windows process wait APIs require FFI calls")]

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE},
};

use super::job::JobObject;
use crate::error::EtwardenError;

/// Monitors a child process for liveness and exit status.
///
/// Wraps a raw process `HANDLE` with query methods suitable for
/// capture-then-wait workflows. Optionally holds a [`JobObject`] to
/// guarantee process tree cleanup on drop.
pub struct ProcessMonitor {
    process: HANDLE,
    pid: u32,
    _job: Option<JobObject>,
}

// SAFETY: ProcessMonitor owns its HANDLE exclusively. Windows HANDLE operations
// are thread-safe at the kernel level. No interior mutability or shared state.
unsafe impl Send for ProcessMonitor {}

impl ProcessMonitor {
    /// Creates a new monitor from a process handle and job object.
    ///
    /// # Arguments
    /// * `pid` — The process ID.
    /// * `process` — The process handle (ownership transferred).
    /// * `job` — The Job Object the process is assigned to.
    #[must_use]
    pub const fn new(pid: u32, process: HANDLE, job: JobObject) -> Self {
        Self {
            process,
            pid,
            _job: Some(job),
        }
    }

    /// Returns the PID of the monitored process.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns true if the process is still running.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        // SAFETY: Handle is valid and owned.
        (unsafe { WaitForSingleObject(self.process, 0) }) == WAIT_TIMEOUT
    }

    /// Blocks until the process exits, returning its exit code.
    ///
    /// # Errors
    /// Returns [`EtwardenError::ProcessSpawn`] if the wait or exit code query fails.
    pub fn wait_exit(&mut self) -> Result<u32, EtwardenError> {
        // SAFETY: Handle is valid and owned.
        let wait = unsafe { WaitForSingleObject(self.process, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            return Err(EtwardenError::ProcessSpawn(format!(
                "WaitForSingleObject failed for PID {}: {wait:?}",
                self.pid
            )));
        }

        let mut exit_code = 0u32;
        // SAFETY: Handle is valid, exit_code is a valid stack variable.
        unsafe { GetExitCodeProcess(self.process, &raw mut exit_code) }
            .map_err(|e| EtwardenError::ProcessSpawn(format!("GetExitCodeProcess failed: {e}")))?;
        Ok(exit_code)
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        // SAFETY: Handle is valid and owned exclusively.
        let _ = unsafe { CloseHandle(self.process) };
    }
}
