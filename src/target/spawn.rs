//! # `target::spawn`
//!
//! **Purpose**: Resolve spawned command output routing, process-tree PID selection, and lifecycle.
//! **Public API**: binary-internal spawn target helpers
//! **Dependencies**: `target`, `etwarden::output`, `etwarden::process`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 135 / 160

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use etwarden::{
    output::diagnostic,
    process::{
        resolve_spawn_capture_target, spawn_and_get_pid_with_options, ProcessMonitor,
        ProcessTreeCache, SpawnOptions,
    },
};

use super::ResolvedTarget;

pub(super) struct SpawnSpec {
    pub(super) cmd: String,
    pub(super) options: SpawnOptions,
}

pub(super) struct SpawnTarget {
    pub(super) root_pid: u32,
    pub(super) pid: u32,
    pub(super) capture_pids: HashSet<u32>,
}

impl SpawnTarget {
    fn fallback(root_pid: u32) -> Self {
        Self {
            root_pid,
            pid: root_pid,
            capture_pids: HashSet::from([root_pid]),
        }
    }

    pub(super) fn from_discovered(
        root_pid: u32,
        pids: HashSet<u32>,
        network_pids: &HashSet<u32>,
    ) -> Self {
        Self {
            root_pid,
            pid: primary_pid(root_pid, &pids, network_pids),
            capture_pids: pids,
        }
    }
}

pub(super) fn primary_pid(root_pid: u32, pids: &HashSet<u32>, network_pids: &HashSet<u32>) -> u32 {
    network_pids
        .iter()
        .copied()
        .min()
        .or_else(|| pids.iter().copied().filter(|pid| *pid != root_pid).min())
        .unwrap_or(root_pid)
}

pub(super) fn should_wait_for_spawn_descendant(cmd: &str) -> bool {
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

pub(super) fn spawn_target(
    spec: &SpawnSpec,
    stop_signal: &Arc<AtomicBool>,
    process_cache: &ProcessTreeCache,
) -> anyhow::Result<ResolvedTarget> {
    let result = spawn_and_get_pid_with_options(&spec.cmd, &spec.options)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let monitor = ProcessMonitor::new(result.child);
    let root_pid = monitor.pid();
    diagnostic::warn(format_args!("spawned PID {root_pid}"));

    let target = match resolve_spawn_capture_target(
        root_pid,
        process_cache,
        should_wait_for_spawn_descendant(&spec.cmd),
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
