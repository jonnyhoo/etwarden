//! # `process::spawn`
//!
//! **Purpose**: Spawn a child process and extract its PID for capture monitoring.
//! **Public API**: `struct SpawnOptions`, `fn spawn_and_get_pid(cmd: &str) -> Result<SpawnResult>`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 130 / 150

use std::process::{Command, Stdio};

use crate::error::EtwardenError;

mod output;

pub use output::SpawnOptions;

/// Result of spawning a child process via `--spawn` mode.
pub struct SpawnResult {
    /// The process ID of the spawned child.
    pub pid: u32,
    /// The raw child handle — pass to `ProcessMonitor::new()`.
    pub child: std::process::Child,
}

/// Spawns a child process and returns its PID and handle without waiting.
///
/// The command string is split into program + args. Quoted paths and quoted
/// arguments are handled (e.g. `"C:\Program Files\app.exe" --name "A B"`).
///
/// # Arguments
/// * `cmd` — The command string to execute.
///
/// # Returns
/// A [`SpawnResult`] containing the child PID and process handle.
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
/// # Returns
/// A [`SpawnResult`] containing the child PID and process handle.
///
/// # Errors
/// Returns [`EtwardenError::ProcessSpawn`] if command parsing, output file setup, or spawn fails.
pub fn spawn_and_get_pid_with_options(
    cmd: &str,
    options: &SpawnOptions,
) -> Result<SpawnResult, EtwardenError> {
    let (program, args) = parse_command(cmd);
    if program.is_empty() {
        return Err(EtwardenError::ProcessSpawn(
            "spawn command must not be empty".into(),
        ));
    }
    let (stdout, stderr) = options.stdio()?;

    let child = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| EtwardenError::ProcessSpawn(format!("failed to spawn '{cmd}': {e}")))?;

    let pid = child.id();
    Ok(SpawnResult { pid, child })
}

/// Splits a command string into (program, args).
///
/// Handles quoted program paths and quoted arguments:
/// `"C:\Program Files\app.exe" --name "A B"` becomes
/// `("C:\Program Files\app.exe", ["--name", "A B"])`.
fn parse_command(cmd: &str) -> (String, Vec<String>) {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return (String::new(), Vec::new());
    }

    let (program, rest) = trimmed.strip_prefix('"').map_or_else(
        || {
            trimmed
                .find(char::is_whitespace)
                .map_or((trimmed, ""), |pos| {
                    (&trimmed[..pos], trimmed[pos..].trim())
                })
        },
        |after_quote| {
            after_quote.find('"').map_or((trimmed, ""), |end| {
                let program = &after_quote[..end];
                let rest = after_quote[end + 1..].trim();
                (program, rest)
            })
        },
    );

    let args = parse_args(rest);

    (program.to_string(), args)
}

fn parse_args(rest: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut started = false;

    for ch in rest.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }

    if started {
        args.push(current);
    }

    args
}

#[cfg(test)]
mod tests;
