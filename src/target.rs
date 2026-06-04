//! # `target`
//!
//! **Purpose**: Resolve CLI target selection and lifecycle stop signaling for the binary.
//! **Public API**: `struct ResolvedTarget`, `fn resolve`, `fn filters`
//! **Dependencies**: `etwarden::cli`, `etwarden::filter`, `etwarden::process`, `ctrlc`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 197 / 220

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
    output::diagnostic,
    process::{resolve_spawn_capture_target, spawn_and_get_pid, ProcessMonitor, ProcessTreeCache},
};

/// Fully resolved target process and its stop signal.
pub struct ResolvedTarget {
    /// Primary process ID reported in the final summary.
    pub pid: u32,
    /// Root process ID for process-tree filtering.
    pub root_pid: u32,
    /// Initial PID set used for filtering and socket bootstrap.
    pub capture_pids: HashSet<u32>,
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
        TargetSpec::Pid(pid) => Ok(ResolvedTarget {
            pid,
            root_pid: pid,
            capture_pids: HashSet::from([pid]),
            is_spawned: false,
            stop_signal,
        }),
        TargetSpec::Spawn(cmd) => spawn_target(&cmd, &stop_signal, process_cache),
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
        vec![Box::new(PidFilter::single(target.pid))]
    }
}

struct SpawnTarget {
    root_pid: u32,
    pid: u32,
    capture_pids: HashSet<u32>,
}

impl SpawnTarget {
    fn fallback(root_pid: u32) -> Self {
        Self {
            root_pid,
            pid: root_pid,
            capture_pids: HashSet::from([root_pid]),
        }
    }

    fn from_discovered(root_pid: u32, pids: HashSet<u32>, network_pids: &HashSet<u32>) -> Self {
        Self {
            root_pid,
            pid: primary_pid(root_pid, &pids, network_pids),
            capture_pids: pids,
        }
    }
}

fn primary_pid(root_pid: u32, pids: &HashSet<u32>, network_pids: &HashSet<u32>) -> u32 {
    network_pids
        .iter()
        .copied()
        .min()
        .or_else(|| pids.iter().copied().filter(|pid| *pid != root_pid).min())
        .unwrap_or(root_pid)
}

fn should_wait_for_spawn_descendant(cmd: &str) -> bool {
    let program = cmd
        .trim()
        .trim_start_matches('"')
        .split(['"', ' ', '\t'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = std::path::Path::new(&program).extension();
    matches!(
        program.as_str(),
        "cmd" | "cmd.exe" | "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
    ) || extension.is_some_and(|ext| matches!(ext.to_str(), Some("cmd" | "bat" | "ps1")))
}

fn spawn_target(
    cmd: &str,
    stop_signal: &Arc<AtomicBool>,
    process_cache: &ProcessTreeCache,
) -> anyhow::Result<ResolvedTarget> {
    let result = spawn_and_get_pid(cmd).map_err(|e| anyhow::anyhow!("{e}"))?;
    let monitor = ProcessMonitor::new(result.child);
    let root_pid = monitor.pid();
    diagnostic::warn(format_args!("spawned PID {root_pid}"));

    let target = match resolve_spawn_capture_target(
        root_pid,
        process_cache,
        should_wait_for_spawn_descendant(cmd),
    ) {
        Ok(target) => SpawnTarget::from_discovered(root_pid, target.pids, &target.network_pids),
        Err(err) => {
            diagnostic::warn(format_args!(
                "spawn network PID discovery failed for PID {root_pid}: {err}"
            ));
            SpawnTarget::fallback(root_pid)
        }
    };
    if target.pid != root_pid {
        diagnostic::warn(format_args!(
            "retargeted spawned PID {root_pid} to network PID {}",
            target.pid
        ));
    }

    spawn_wait_thread(monitor, stop_signal);
    Ok(ResolvedTarget {
        pid: target.pid,
        root_pid: target.root_pid,
        capture_pids: target.capture_pids,
        is_spawned: true,
        stop_signal: Arc::clone(stop_signal),
    })
}

enum TargetSpec {
    Pid(u32),
    Spawn(String),
}

fn target_spec(cli: &Cli) -> anyhow::Result<TargetSpec> {
    match (&cli.target, cli.pid, &cli.spawn) {
        (None, Some(0), None) => anyhow::bail!("PID must be greater than zero"),
        (Some(TargetMode::Pid { pid }), None, None) if *pid == 0 => {
            anyhow::bail!("PID must be greater than zero");
        }
        (None, Some(pid), None) => Ok(TargetSpec::Pid(pid)),
        (Some(TargetMode::Pid { pid }), None, None) => Ok(TargetSpec::Pid(*pid)),
        (None, None, Some(cmd)) | (Some(TargetMode::Spawn { cmd }), None, None) => {
            Ok(TargetSpec::Spawn(cmd.clone()))
        }
        (None, None, None) => {
            anyhow::bail!("specify --pid <PID>, --spawn <command>, or a target subcommand");
        }
        _ => anyhow::bail!("cannot specify more than one target"),
    }
}

fn spawn_wait_thread(mut monitor: ProcessMonitor, stop_signal: &Arc<AtomicBool>) {
    let thread_signal = Arc::clone(stop_signal);
    std::thread::spawn(move || {
        let pid = monitor.pid();
        match monitor.wait_exit() {
            Ok(code) => diagnostic::warn(format_args!("child PID {pid} exited with code {code}")),
            Err(err) => diagnostic::warn(format_args!("child monitor error: {err}")),
        }
        thread_signal.store(true, Ordering::SeqCst);
    });
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
