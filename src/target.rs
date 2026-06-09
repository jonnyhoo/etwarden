//! # `target`
//!
//! **Purpose**: Resolve CLI target selection and lifecycle stop signaling for the binary.
//! **Public API**: `struct ResolvedTarget`, `fn resolve`, `fn filters`
//! **Dependencies**: `etwarden::cli`, `etwarden::filter`, `etwarden::process`, `ctrlc`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 140 / 180

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use etwarden::{
    cli::{Cli, TargetMode},
    filter::{pid::PidFilter, tree::ProcessTreeFilter, Filter},
    process::{spawn::SpawnOptions, tree::ProcessTreeCache},
};

mod spawn;

use spawn::{spawn_target, SpawnSpec};

/// Fully resolved target process and its stop signal.
pub struct ResolvedTarget {
    /// Primary process ID reported in the final summary.
    pub pid: u32,
    /// Root process ID for process-tree filtering.
    pub root_pid: u32,
    /// Initial PID set used for filtering and socket bootstrap.
    pub capture_pids: HashSet<u32>,
    /// Spawn-descendant PIDs that owned TCP sockets during discovery.
    pub network_pids: HashSet<u32>,
    /// Whether the target came from `--spawn`.
    pub is_spawned: bool,
    /// Shared signal set by Ctrl+C or child process exit.
    pub stop_signal: Arc<AtomicBool>,
}

/// Resolves the CLI target and installs stop signaling.
///
/// # Arguments
/// * `cli` — Parsed CLI options.
///
/// # Returns
/// A `ResolvedTarget` with PID and stop signal.
///
/// # Errors
/// Returns an error when target flags conflict, spawn fails, or Ctrl+C handler install fails.
pub fn resolve(cli: &Cli, process_cache: &ProcessTreeCache) -> anyhow::Result<ResolvedTarget> {
    let stop_signal = Arc::new(AtomicBool::new(false));
    install_ctrlc_handler(&stop_signal)?;

    match target_spec(cli)? {
        TargetSpec::Pid(pid) => Ok(pid_target(pid, stop_signal)),
        TargetSpec::Spawn(spec) => spawn_target(&spec, &stop_signal, process_cache),
    }
}

fn pid_target(pid: u32, stop_signal: Arc<AtomicBool>) -> ResolvedTarget {
    ResolvedTarget {
        pid,
        root_pid: pid,
        capture_pids: HashSet::from([pid]),
        network_pids: HashSet::new(),
        is_spawned: false,
        stop_signal,
    }
}

/// Builds event filters for the resolved target.
///
/// # Arguments
/// * `target` — Resolved capture target.
/// * `process_cache` — Shared process tree cache for dynamic spawned descendants.
///
/// # Returns
/// A filter list suitable for [`etwarden::capture::CaptureConfig`].
#[must_use]
pub fn filters(
    target: &ResolvedTarget,
    process_cache: Arc<ProcessTreeCache>,
) -> Vec<Box<dyn Filter>> {
    if target.is_spawned {
        vec![Box::new(ProcessTreeFilter::new(
            target.root_pid,
            process_cache,
            target.capture_pids.clone(),
        ))]
    } else {
        vec![Box::new(PidFilter::new(target.capture_pids.clone()))]
    }
}

enum TargetSpec {
    Pid(u32),
    Spawn(SpawnSpec),
}

fn target_spec(cli: &Cli) -> anyhow::Result<TargetSpec> {
    match (&cli.target, cli.pid, &cli.spawn) {
        (None, Some(_), None) | (Some(TargetMode::Pid { .. }), None, None)
            if cli.spawn_stdout.is_some() || cli.spawn_stderr.is_some() =>
        {
            anyhow::bail!("--spawn-stdout and --spawn-stderr require a spawn target");
        }
        (None, Some(0), None) => anyhow::bail!("PID must be greater than zero"),
        (Some(TargetMode::Pid { pid }), None, None) if *pid == 0 => {
            anyhow::bail!("PID must be greater than zero");
        }
        (None, Some(pid), None) => Ok(TargetSpec::Pid(pid)),
        (Some(TargetMode::Pid { pid }), None, None) => Ok(TargetSpec::Pid(*pid)),
        (None, None, Some(cmd)) | (Some(TargetMode::Spawn { cmd }), None, None) => {
            Ok(TargetSpec::Spawn(SpawnSpec {
                cmd: cmd.clone(),
                options: SpawnOptions {
                    stdout_path: cli.spawn_stdout.clone(),
                    stderr_path: cli.spawn_stderr.clone(),
                },
            }))
        }
        (None, None, None) => {
            anyhow::bail!("specify --pid <PID>, --spawn <command>, or a target subcommand");
        }
        _ => anyhow::bail!("cannot specify more than one target"),
    }
}

fn install_ctrlc_handler(stop_signal: &Arc<AtomicBool>) -> anyhow::Result<()> {
    let handler_signal = Arc::clone(stop_signal);
    ctrlc::set_handler(move || {
        handler_signal.store(true, Ordering::SeqCst);
    })
    .map_err(|e| anyhow::anyhow!("failed to install Ctrl+C handler: {e}"))
}

#[cfg(test)]
mod tests;
