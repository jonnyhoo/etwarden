//! # `cli::target`
//!
//! **Purpose**: Capture and process target subcommands.
//! **Public API**: `enum TargetMode`
//! **Dependencies**: `cli::process`, `clap`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 47 / 80

use std::path::PathBuf;

use super::ProcessCommand;

/// How to target the process to monitor.
#[derive(Debug, clap::Subcommand)]
pub enum TargetMode {
    /// Monitor a specific PID.
    Pid {
        /// The process ID to monitor.
        pid: u32,
    },
    /// Spawn a command and monitor it.
    Spawn {
        /// The command to execute.
        cmd: String,
    },
    /// Launch a browser, navigate to a URL, and capture network traffic.
    Browse {
        /// URL to navigate to.
        url: String,
        /// Browser to use: chrome, edge, chromium, brave, vivaldi.
        #[arg(long)]
        browser: Option<String>,
        /// Run browser in headless mode.
        #[arg(long)]
        headless: bool,
        /// Explicit path to browser executable.
        #[arg(long)]
        browser_path: Option<PathBuf>,
        /// Seconds to wait for page load (default 15).
        #[arg(long, default_value = "15")]
        timeout: u64,
        /// Seconds to keep capturing after page load (default 0).
        #[arg(long, default_value = "0")]
        after_load: u64,
    },
    /// Inspect or terminate local processes. Emits NDJSON only.
    Process {
        /// Process inventory operation.
        #[command(subcommand)]
        command: ProcessCommand,
    },
}
