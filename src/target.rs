//! # `target`
//!
//! **Purpose**: Resolve CLI target selection and lifecycle stop signaling for the binary.
//! **Public API**: `struct ResolvedTarget`, `fn resolve`
//! **Dependencies**: `etwarden::cli`, `etwarden::process`, `ctrlc`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 128 / 140

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use etwarden::{
    cli::{Cli, TargetMode},
    process::{spawn_and_get_pid, ProcessMonitor},
};

/// Fully resolved target process and its stop signal.
pub struct ResolvedTarget {
    /// Process ID to monitor.
    pub pid: u32,
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
pub fn resolve(cli: &Cli) -> anyhow::Result<ResolvedTarget> {
    let stop_signal = Arc::new(AtomicBool::new(false));
    install_ctrlc_handler(&stop_signal)?;

    let pid = match target_spec(cli)? {
        TargetSpec::Pid(pid) => pid,
        TargetSpec::Spawn(cmd) => spawn_target(&cmd, &stop_signal)?,
    };

    Ok(ResolvedTarget { pid, stop_signal })
}

enum TargetSpec {
    Pid(u32),
    Spawn(String),
}

fn target_spec(cli: &Cli) -> anyhow::Result<TargetSpec> {
    match (&cli.target, cli.pid, &cli.spawn) {
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

fn spawn_target(cmd: &str, stop_signal: &Arc<AtomicBool>) -> anyhow::Result<u32> {
    let result = spawn_and_get_pid(cmd).map_err(|e| anyhow::anyhow!("{e}"))?;
    let monitor = ProcessMonitor::new(result.child);
    let pid = monitor.pid();
    eprintln!("[etwarden] spawned PID {pid}");
    spawn_wait_thread(monitor, stop_signal);
    Ok(pid)
}

fn spawn_wait_thread(mut monitor: ProcessMonitor, stop_signal: &Arc<AtomicBool>) {
    let thread_signal = Arc::clone(stop_signal);
    std::thread::spawn(move || {
        let pid = monitor.pid();
        match monitor.wait_exit() {
            Ok(code) => eprintln!("[etwarden] child PID {pid} exited with code {code}"),
            Err(err) => eprintln!("[etwarden] child monitor error: {err}"),
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
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn target_spec_accepts_pid_flag() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "42"]).expect("parse");
        let TargetSpec::Pid(pid) = target_spec(&cli).expect("target") else {
            unreachable!("expected PID target");
        };
        assert_eq!(pid, 42);
    }

    #[test]
    fn target_spec_accepts_pid_subcommand() {
        let cli = Cli::try_parse_from(["etwarden", "pid", "42"]).expect("parse");
        let TargetSpec::Pid(pid) = target_spec(&cli).expect("target") else {
            unreachable!("expected PID target");
        };
        assert_eq!(pid, 42);
    }

    #[test]
    fn target_spec_rejects_mixed_targets() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "42", "spawn", "cmd /C exit 0"])
            .expect("parse");
        assert!(target_spec(&cli).is_err());
    }
}
