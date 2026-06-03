//! # `cli`
//!
//! **Purpose**: Command-line argument definitions via clap.
//! **Public API**: `struct Cli`, `enum TargetMode`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 62 / 100

use clap::Parser;

/// Process-level network capture CLI for agent runtime consumption.
#[derive(Debug, Parser)]
#[command(name = "etwarden", version, about)]
pub struct Cli {
    /// How to identify the target process.
    #[command(subcommand)]
    pub target: Option<TargetMode>,

    /// Monitor a specific process by PID.
    #[arg(long)]
    pub pid: Option<u32>,

    /// Spawn a command and monitor the child process.
    #[arg(long)]
    pub spawn: Option<String>,

    /// Capture duration in seconds. 0 = until Ctrl+C or child exits.
    #[arg(long, default_value = "0")]
    pub duration: u64,

    /// Write raw packets to a pcapng file.
    #[arg(long)]
    pub pcap_out: Option<String>,

    /// Pretty-print JSON output (for debugging).
    #[arg(long)]
    pub json_pretty: bool,
}

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parses_pid_flag() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");
        assert_eq!(cli.pid, Some(1234));
    }

    #[test]
    fn cli_parses_spawn_flag() {
        let cli = Cli::try_parse_from(["etwarden", "--spawn", "curl.exe https://example.com"])
            .expect("parse");
        assert_eq!(cli.spawn, Some("curl.exe https://example.com".into()));
    }

    #[test]
    fn cli_parses_duration() {
        let cli =
            Cli::try_parse_from(["etwarden", "--pid", "1234", "--duration", "10"]).expect("parse");
        assert_eq!(cli.duration, 10);
    }

    #[test]
    fn cli_parses_pcap_out() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234", "--pcap-out", "out.pcapng"])
            .expect("parse");
        assert_eq!(cli.pcap_out, Some("out.pcapng".into()));
    }

    #[test]
    fn cli_default_duration_is_zero() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1"]).expect("parse");
        assert_eq!(cli.duration, 0);
    }

    #[test]
    fn cli_rejects_invalid_pid() {
        let result = Cli::try_parse_from(["etwarden", "--pid", "abc"]);
        assert!(result.is_err());
    }
}
