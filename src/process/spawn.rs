//! # `process::spawn`
//!
//! **Purpose**: Spawn a child process via `CreateProcessW` and extract its PID for capture monitoring.
//! **Public API**: `struct SpawnOptions`, `fn spawn_and_get_pid(cmd: &str) -> Result<SpawnResult>`
//! **Dependencies**: `error`, `windows`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 200

#![expect(unsafe_code, reason = "Windows process creation requires FFI calls")]

use std::mem;

use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Console::{GetStdHandle, STD_ERROR_HANDLE},
            Threading::{
                CreateProcessW, ResumeThread, TerminateProcess, CREATE_SUSPENDED,
                PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
            },
        },
    },
};

use crate::error::EtwardenError;

mod output;

use output::inheritable_sa;
pub use output::SpawnOptions;

/// Result of spawning a child process via `--spawn` mode.
///
/// Owns the process and thread handles. Call [`SpawnResult::assign_resume_into`]
/// to assign to a job, resume execution, and extract the process handle.
pub struct SpawnResult {
    /// The process ID of the spawned child.
    pub pid: u32,
    process: HANDLE,
    thread: HANDLE,
}

/// Spawns a child process and returns its PID and handles without waiting.
///
/// Uses `CreateProcessW` with `CREATE_SUSPENDED` so the caller can assign
/// the process to a Job Object before execution begins (no race).
///
/// The raw command string is passed directly to `CreateProcessW` — no
/// manual parsing needed. `.cmd`/`.bat` wrappers are resolved natively.
///
/// # Arguments
/// * `cmd` — The command string to execute.
///
/// # Errors
/// Returns [`EtwardenError::ProcessSpawn`] if the spawn fails.
pub fn spawn_and_get_pid(cmd: &str) -> Result<SpawnResult, EtwardenError> {
    spawn_and_get_pid_with_options(cmd, &SpawnOptions::default())
}

/// Spawns a child process with explicit output routing options.
///
/// Parent stdout remains independent from child stdout so etwarden can keep stdout NDJSON-only.
///
/// # Arguments
/// * `cmd` — The command string to execute.
/// * `options` — Child stdout/stderr file routing.
///
/// # Errors
/// Returns [`EtwardenError::ProcessSpawn`] if output file setup or spawn fails.
pub fn spawn_and_get_pid_with_options(
    cmd: &str,
    options: &SpawnOptions,
) -> Result<SpawnResult, EtwardenError> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err(EtwardenError::ProcessSpawn(
            "spawn command must not be empty".into(),
        ));
    }

    // Wrap with cmd.exe /C so .cmd/.bat files on PATH resolve correctly.
    // CreateProcessW with lpApplicationName=NULL only searches for .exe files.
    let full_cmd = format!("cmd.exe /C {cmd}");
    let mut cmd_utf16: Vec<u16> = full_cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let (startup, owned_handles) = build_startup_info(options)?;

    let mut proc_info = PROCESS_INFORMATION::default();

    // SAFETY: CreateProcessW with null lpApplicationName uses the first token
    // of lpCommandLine as the module. cmd.exe is always on PATH.
    let result = unsafe {
        CreateProcessW(
            None,
            PWSTR(cmd_utf16.as_mut_ptr()),
            None,
            None,
            true, // bInheritHandles
            CREATE_SUSPENDED,
            None,
            None,
            &raw const startup,
            &raw mut proc_info,
        )
    };

    // Close our copies of created std handles (child has inherited copies).
    for h in owned_handles {
        let _ = unsafe { CloseHandle(h) };
    }

    result.map_err(|e| {
        EtwardenError::ProcessSpawn(format!("CreateProcessW failed for '{cmd}': {e}"))
    })?;

    Ok(SpawnResult {
        pid: proc_info.dwProcessId,
        process: proc_info.hProcess,
        thread: proc_info.hThread,
    })
}

impl SpawnResult {
    /// Returns the process handle (for job assignment).
    #[must_use]
    pub const fn process_handle(&self) -> HANDLE {
        self.process
    }

    /// Returns the primary thread handle (for `ResumeThread`).
    #[must_use]
    pub const fn thread_handle(&self) -> HANDLE {
        self.thread
    }

    /// Assigns to a job object, resumes execution, closes thread handle.
    ///
    /// Returns `(pid, process_handle)` for [`crate::process::ProcessMonitor`].
    /// Caller owns the process handle and must close it (via `ProcessMonitor` drop).
    ///
    /// # Errors
    /// Returns [`EtwardenError::ProcessSpawn`] if job assignment or resume fails.
    pub fn assign_resume_into(
        self,
        assign_fn: impl Fn(HANDLE) -> Result<(), String>,
    ) -> Result<(u32, HANDLE), EtwardenError> {
        if let Err(err) = assign_fn(self.process) {
            // SAFETY: Process handle is valid; the process is still suspended
            // and not assigned to the job, so terminate it to avoid an orphan.
            let _ = unsafe { TerminateProcess(self.process, 1) };
            return Err(EtwardenError::ProcessSpawn(format!(
                "job assign failed: {err}"
            )));
        }

        // SAFETY: Thread handle is valid, just returned by CreateProcessW.
        let prev = unsafe { ResumeThread(self.thread) };
        if prev == u32::MAX {
            return Err(EtwardenError::ProcessSpawn(
                "ResumeThread failed: invalid thread handle".into(),
            ));
        }

        let pid = self.pid;
        let process = self.process;
        // Close thread handle (not needed after resume).
        // SAFETY: Thread handle is valid and no longer needed.
        let _ = unsafe { CloseHandle(self.thread) };
        // Prevent Drop from double-closing.
        std::mem::forget(self);
        Ok((pid, process))
    }
}

impl Drop for SpawnResult {
    fn drop(&mut self) {
        // SAFETY: Handles are valid and owned exclusively.
        let _ = unsafe { CloseHandle(self.thread) };
        let _ = unsafe { CloseHandle(self.process) };
    }
}

/// Builds `STARTUPINFOW` with std handle routing.
///
/// Returns the startup info and a list of handles we created that must be
/// closed after `CreateProcessW` (the child has inherited copies).
fn build_startup_info(
    options: &SpawnOptions,
) -> Result<(STARTUPINFOW, Vec<HANDLE>), EtwardenError> {
    let mut owned = Vec::new();

    // stdin: always NUL (discard)
    let stdin = nul_handle_read()?;
    owned.push(stdin);

    // stdout: user file or NUL (discard)
    let stdout = if let Some(handle) = options.stdout_handle()? {
        owned.push(handle);
        handle
    } else {
        let h = nul_handle_write()?;
        owned.push(h);
        h
    };

    // stderr: user file or inherit parent
    let stderr = options.stderr_handle()?.map_or_else(
        || {
            // GetStdHandle returns a borrowed handle — do NOT close it.
            unsafe { GetStdHandle(STD_ERROR_HANDLE) }
                .inspect_err(|e| {
                    crate::output::diagnostic::warn(format_args!(
                        "GetStdHandle(STD_ERROR_HANDLE) failed: {e}"
                    ));
                })
                .unwrap_or_else(|_| HANDLE::default())
        },
        |handle| {
            owned.push(handle);
            handle
        },
    );

    let startup = STARTUPINFOW {
        cb: u32::try_from(mem::size_of::<STARTUPINFOW>()).expect("STARTUPINFOW size fits u32"),
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: stdin,
        hStdOutput: stdout,
        hStdError: stderr,
        ..Default::default()
    };

    Ok((startup, owned))
}

fn nul_handle_read() -> Result<HANDLE, EtwardenError> {
    let wide: Vec<u16> = "NUL\0".encode_utf16().collect();
    let sa = inheritable_sa();
    // SAFETY: CreateFileW with NUL device, inheritable SA.
    unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(std::ptr::addr_of!(sa)),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| EtwardenError::ProcessSpawn(format!("failed to open NUL for stdin: {e}")))
}

fn nul_handle_write() -> Result<HANDLE, EtwardenError> {
    let wide: Vec<u16> = "NUL\0".encode_utf16().collect();
    let sa = inheritable_sa();
    // SAFETY: CreateFileW with NUL device, inheritable SA.
    unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(std::ptr::addr_of!(sa)),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| EtwardenError::ProcessSpawn(format!("failed to open NUL: {e}")))
}

#[cfg(test)]
mod tests;
