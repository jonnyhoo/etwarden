//! # `process::spawn::output`
//!
//! **Purpose**: Configure file-backed stdout/stderr routing for spawned children.
//! **Public API**: `struct SpawnOptions`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 100

use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::Stdio,
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
    pub(super) fn stdio(&self) -> Result<(Stdio, Stdio), EtwardenError> {
        if self.stdout_path.is_some() && self.stdout_path == self.stderr_path {
            return Err(EtwardenError::ProcessSpawn(
                "spawn stdout and stderr paths must differ".into(),
            ));
        }

        let stdout = output_stdio(self.stdout_path.as_deref(), Stdio::null(), "stdout")?;
        let stderr = output_stdio(self.stderr_path.as_deref(), Stdio::inherit(), "stderr")?;
        Ok((stdout, stderr))
    }
}

fn output_stdio(path: Option<&Path>, default: Stdio, stream: &str) -> Result<Stdio, EtwardenError> {
    path.map_or(Ok(default), |path| {
        output_file(path, stream).map(Stdio::from)
    })
}

fn output_file(path: &Path, stream: &str) -> Result<File, EtwardenError> {
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
    File::create(path).map_err(|e| {
        EtwardenError::ProcessSpawn(format!(
            "failed to create spawn {stream} file '{}': {e}",
            path.display()
        ))
    })
}
