//! # `process::job`
//!
//! **Purpose**: Windows Job Object wrapper for process tree lifecycle management.
//! **Public API**: `struct JobObject`
//! **Dependencies**: `windows`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 110 / 140

#![expect(
    unsafe_code,
    reason = "Windows Job Object management requires FFI calls"
)]

use std::mem;

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE},
        },
    },
};

/// A Windows Job Object that kills all assigned processes when the handle is closed.
///
/// Uses `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` so the OS terminates the entire
/// process tree when the job handle is closed (on drop or process exit).
///
/// # Thread safety
/// `JobObject` is `Send` because the handle is exclusively owned — no shared mutation.
/// It is `Sync` because `&JobObject` only exposes `&self` methods that perform
/// thread-safe Windows syscalls.
pub struct JobObject {
    handle: HANDLE,
}

// SAFETY: JobObject owns its HANDLE exclusively. Windows HANDLE operations are
// thread-safe at the kernel level. No interior mutability or shared state.
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

impl JobObject {
    /// Creates a new anonymous Job Object with `KILL_ON_JOB_CLOSE`.
    ///
    /// # Errors
    /// Returns a descriptive string if the Windows API calls fail.
    pub fn new() -> Result<Self, String> {
        // SAFETY: CreateJobObjectW with null params creates an anonymous job object.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| format!("CreateJobObjectW failed: {e}"))?;

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // SAFETY: info is a valid stack-allocated struct, size is correct.
        let set_result = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                u32::try_from(mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .expect("JOBOBJECT_EXTENDED_LIMIT_INFORMATION size fits u32"),
            )
        };

        if let Err(e) = set_result {
            // SAFETY: Handle was just created, still valid.
            let _ = unsafe { CloseHandle(handle) };
            return Err(format!("SetInformationJobObject failed: {e}"));
        }

        Ok(Self { handle })
    }

    /// Opens a process by PID and assigns it to this Job Object.
    ///
    /// # Errors
    /// Returns a descriptive string if `OpenProcess` or `AssignProcessToJobObject` fails.
    pub fn assign_pid(&self, pid: u32) -> Result<(), String> {
        // SAFETY: Opening a process handle with well-defined access rights.
        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid) }
            .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;

        // SAFETY: Both handles are valid; job was created by us, process just opened.
        let result = unsafe { AssignProcessToJobObject(self.handle, process) };

        // SAFETY: Process handle is no longer needed regardless of result.
        let _ = unsafe { CloseHandle(process) };

        result.map_err(|e| format!("AssignProcessToJobObject({pid}) failed: {e}"))
    }

    /// Assigns an already-opened process handle to this Job Object.
    ///
    /// Use this when the process was created with `CreateProcessW` and the
    /// handle is already available (avoids the `OpenProcess` round-trip).
    ///
    /// # Errors
    /// Returns a descriptive string if `AssignProcessToJobObject` fails.
    pub fn assign_handle(&self, process: HANDLE) -> Result<(), String> {
        // SAFETY: Both handles are valid; job was created by us, process handle provided by caller.
        unsafe { AssignProcessToJobObject(self.handle, process) }
            .map_err(|e| format!("AssignProcessToJobObject failed: {e}"))
    }

    /// Terminates all processes in the Job Object immediately.
    ///
    /// # Errors
    /// Returns a descriptive string if `TerminateJobObject` fails.
    pub fn terminate(&self, exit_code: u32) -> Result<(), String> {
        // SAFETY: Handle is valid and owned by this JobObject.
        unsafe { TerminateJobObject(self.handle, exit_code) }
            .map_err(|e| format!("TerminateJobObject failed: {e}"))
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        // SAFETY: Handle is valid and owned exclusively by this JobObject.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}
