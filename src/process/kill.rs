//! # `process::kill`
//!
//! **Purpose**: Exact-PID process termination via stable Win32 API.
//! **Public API**: `struct KillProcessResult`, `fn kill_process`
//! **Dependencies**: `error`, `process::inventory`, `windows`
//! **Platform**: `windows-only`
//! **Privilege**: `none` unless target process requires elevation
//! **Line budget**: 82 / 120

#![expect(unsafe_code, reason = "Windows process termination requires FFI calls")]

use windows::Win32::{
    Foundation::CloseHandle,
    System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
};

use crate::{
    error::EtwardenError,
    process::{filtered_processes, ProcessEntry, ProcessFilter},
};

/// Result of one exact-PID termination attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillProcessResult {
    /// Exact PID requested by caller.
    pub pid: u32,
    /// Process metadata captured before termination.
    pub process: Option<ProcessEntry>,
    /// Whether `TerminateProcess` succeeded.
    pub success: bool,
    /// Win32 backend action.
    pub action: String,
    /// Error text when termination failed.
    pub error: Option<String>,
}

/// Terminates exactly one PID. Name/filter-based kill is intentionally unsupported.
///
/// # Arguments
/// * `pid` — Exact process ID to terminate.
/// * `all_sessions` — Whether a process outside the current session may be targeted.
/// * `exit_code` — Exit code passed to `TerminateProcess`.
///
/// # Errors
/// Returns [`EtwardenError::ProcessControl`] for invalid PID, session mismatch,
/// missing process, `OpenProcess`, or `TerminateProcess` failures.
pub fn kill_process(
    pid: u32,
    all_sessions: bool,
    exit_code: u32,
) -> Result<KillProcessResult, EtwardenError> {
    if pid == 0 {
        return Err(EtwardenError::ProcessControl(
            "PID must be greater than zero".into(),
        ));
    }
    if pid == std::process::id() {
        return Err(EtwardenError::ProcessControl(
            "refusing to kill current etwarden process".into(),
        ));
    }

    let process = resolve_target_process(pid, all_sessions)?;
    terminate_exact_pid(pid, exit_code).map_err(|error| {
        EtwardenError::ProcessControl(format!("failed to terminate PID {pid}: {error}"))
    })?;

    Ok(KillProcessResult {
        pid,
        process: Some(process),
        success: true,
        action: "terminate_process".into(),
        error: None,
    })
}

fn resolve_target_process(pid: u32, all_sessions: bool) -> Result<ProcessEntry, EtwardenError> {
    let filter = ProcessFilter {
        pid: Some(pid),
        text: None,
        all_sessions,
    };
    filtered_processes(&filter)
        .into_iter()
        .next()
        .ok_or_else(|| EtwardenError::ProcessControl(format!("PID {pid} not found or not allowed")))
}

fn terminate_exact_pid(pid: u32, exit_code: u32) -> Result<(), String> {
    // SAFETY: OpenProcess is called with PROCESS_TERMINATE only and a concrete PID.
    let handle =
        unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }.map_err(|e| e.to_string())?;
    // SAFETY: Handle was returned by OpenProcess and is valid until CloseHandle below.
    let result = unsafe { TerminateProcess(handle, exit_code) }.map_err(|e| e.to_string());
    // SAFETY: Handle was opened by OpenProcess in this function and must be closed once.
    let _ = unsafe { CloseHandle(handle) };
    result
}
