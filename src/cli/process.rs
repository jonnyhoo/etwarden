//! # `cli::process`
//!
//! **Purpose**: Agent-first process inventory subcommands.
//! **Public API**: `enum ProcessCommand`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 49 / 80

/// Process inventory and lifecycle commands.
#[derive(Debug, clap::Subcommand)]
pub enum ProcessCommand {
    /// List local processes as NDJSON `process` lines.
    List {
        /// Case-insensitive substring matched against name, exe, or command line.
        #[arg(long)]
        filter: Option<String>,
        /// Exact PID filter. Does not terminate anything.
        #[arg(long)]
        pid: Option<u32>,
        /// Include services and other sessions. Default is current session only.
        #[arg(long)]
        all: bool,
    },
    /// List one process tree as NDJSON `process` lines.
    Tree {
        /// Root process ID.
        #[arg(long)]
        pid: u32,
        /// Include services and other sessions. Default is current session only.
        #[arg(long)]
        all: bool,
    },
    /// Force-terminate one exact PID. No name/filter kill path exists.
    Kill {
        /// Exact process ID to terminate.
        #[arg(long)]
        pid: u32,
        /// Required acknowledgement for destructive termination.
        #[arg(long)]
        force: bool,
        /// Include services and other sessions. Default is current session only.
        #[arg(long)]
        all: bool,
        /// Exit code passed to TerminateProcess.
        #[arg(long, default_value = "1")]
        exit_code: u32,
    },
}
