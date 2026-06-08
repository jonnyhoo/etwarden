//! # `process::spawn::output`
//!
//! **Purpose**: Configure file-backed stdout/stderr routing for spawned children.
//! **Public API**: `struct SpawnOptions`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 100

use std::{
    fs, mem,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
};

use windows::Win32::{
    Foundation::{GENERIC_WRITE, HANDLE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};

use crate::error::EtwardenError;

/// Output routing options for a spawned child.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpawnOptions {
    /// File path receiving child stdout. `None` discards stdout to preserve NDJSON-only parent stdout.
    pub stdout_path: Option<PathBuf>,
    /// File path receiving child stderr. `None` inherits stderr for current diagnostic-compatible behavior.
    pub stderr_path: Option<PathBuf>,
}

impl SpawnOptions {
    /// Opens output file for stdout as an inheritable handle.
    ///
    /// Returns `Some(HANDLE)` if a path was specified, or `None` for default (null).
    /// Handle is created with `SECURITY_ATTRIBUTES { bInheritHandle: TRUE }`.
    ///
    /// # Errors
    /// Returns [`EtwardenError::ProcessSpawn`] if the file cannot be created.
    pub(super) fn stdout_handle(&self) -> Result<Option<HANDLE>, EtwardenError> {
        self.stdout_path
            .as_deref()
            .map(|p| output_handle(p, "stdout"))
            .transpose()
    }

    /// Opens output file for stderr as an inheritable handle.
    ///
    /// Returns `Some(HANDLE)` if a path was specified, or `None` for default (inherit).
    /// Handle is created with `SECURITY_ATTRIBUTES { bInheritHandle: TRUE }`.
    ///
    /// # Errors
    /// Returns [`EtwardenError::ProcessSpawn`] if paths conflict or the file cannot be created.
    pub(super) fn stderr_handle(&self) -> Result<Option<HANDLE>, EtwardenError> {
        if self.stdout_path.is_some() && self.stdout_path == self.stderr_path {
            return Err(EtwardenError::ProcessSpawn(
                "spawn stdout and stderr paths must differ".into(),
            ));
        }
        self.stderr_path
            .as_deref()
            .map(|p| output_handle(p, "stderr"))
            .transpose()
    }
}

/// Inheritable `SECURITY_ATTRIBUTES` for `CreateFileW`.
pub(super) fn inheritable_sa() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(mem::size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits u32"),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: true.into(),
    }
}

fn output_handle(path: &Path, stream: &str) -> Result<HANDLE, EtwardenError> {
    if path.as_os_str().is_empty() {
        return Err(EtwardenError::ProcessSpawn(format!(
            "spawn {stream} path must not be empty"
        )));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|e| {
            EtwardenError::ProcessSpawn(format!(
                "failed to create spawn {stream} directory '{}': {e}",
                parent.display()
            ))
        })?;
    }
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sa = inheritable_sa();
    // SAFETY: CreateFileW with valid path, inheritable SA, no template file.
    unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(ptr::addr_of!(sa)),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| {
        EtwardenError::ProcessSpawn(format!(
            "failed to create spawn {stream} file '{}': {e}",
            path.display()
        ))
    })
}
