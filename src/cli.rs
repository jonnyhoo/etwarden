//! # `cli`
//!
//! **Purpose**: Command-line argument definitions via clap.
//! **Public API**: `struct Cli`, `enum TargetMode`, `enum BrowseMode`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 124 / 150

use std::{net::SocketAddr, path::PathBuf};

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

    /// Write spawned child stdout to a file. Parent stdout remains NDJSON-only.
    #[arg(long)]
    pub spawn_stdout: Option<PathBuf>,

    /// Write spawned child stderr to a file instead of inheriting parent stderr.
    #[arg(long)]
    pub spawn_stderr: Option<PathBuf>,

    /// Capture duration in seconds. 0 = until Ctrl+C or child exits.
    #[arg(long, default_value = "0")]
    pub duration: u64,

    /// Write raw packets to a pcapng file.
    #[arg(long)]
    pub pcap_out: Option<String>,

    /// Disable HTTPS MITM even if an active routing mode is selected.
    #[arg(long)]
    pub no_mitm: bool,

    /// Local MITM proxy listen address.
    #[arg(long, default_value = "127.0.0.1:3003")]
    pub mitm_listen: SocketAddr,

    /// MITM root CA certificate path.
    #[arg(long, default_value = "etwarden-mitm-ca.crt")]
    pub mitm_ca_cert: PathBuf,

    /// MITM root CA private key path.
    #[arg(long, default_value = "etwarden-mitm-ca.key")]
    pub mitm_ca_key: PathBuf,

    /// Max decoded body bytes emitted into NDJSON per decrypted HTTP event.
    #[arg(long, default_value = "1048576")]
    pub mitm_body_limit: usize,

    /// Max body bytes buffered from the proxy before forwarding.
    #[arg(long, default_value = "1048576")]
    pub mitm_max_body_bytes: usize,

    /// Opt in to legacy global OS proxy mutation. Requires `--no-divert`.
    #[arg(long, requires = "no_divert", conflicts_with = "no_mitm")]
    pub mitm_system_proxy: bool,

    /// Enable experimental `WinDivert` TCP redirect for hot-attach MITM.
    #[arg(long, conflicts_with_all = ["no_divert", "no_mitm"])]
    pub divert: bool,

    /// Limit `--divert` transparent redirect to destination ports, comma-separated.
    #[arg(long, value_delimiter = ',', conflicts_with = "no_divert")]
    pub divert_ports: Vec<u16>,

    /// Exclude destination ports from `--divert`, comma-separated.
    #[arg(long, value_delimiter = ',', conflicts_with = "no_divert")]
    pub divert_exclude_ports: Vec<u16>,

    /// Actively MITM transparent TLS instead of raw-tunneling it. Requires trusted MITM CA.
    #[arg(long, requires = "divert", conflicts_with_all = ["no_divert", "no_mitm"])]
    pub divert_tls_mitm: bool,

    /// Keep `WinDivert` TCP redirect disabled. Default until transparent upstream handling is complete.
    #[arg(long)]
    pub no_divert: bool,

    /// Path to a JSON rules file (replace/intercept/hosts/block rules).
    #[arg(long)]
    pub rules: Option<PathBuf>,
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
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

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
    fn cli_parses_spawn_output_paths() {
        let cli = Cli::try_parse_from([
            "etwarden",
            "--spawn",
            "cmd /C exit 0",
            "--spawn-stdout",
            "captures/result.json",
            "--spawn-stderr",
            "captures/result.err",
        ])
        .expect("parse");

        assert_eq!(
            cli.spawn_stdout,
            Some(PathBuf::from("captures/result.json"))
        );
        assert_eq!(cli.spawn_stderr, Some(PathBuf::from("captures/result.err")));
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
    fn cli_parses_mitm_options() {
        // MITM is on by default; --mitm-* flags still work for tuning.
        let cli = Cli::try_parse_from([
            "etwarden",
            "--pid",
            "1234",
            "--mitm-listen",
            "127.0.0.1:4000",
            "--mitm-body-limit",
            "1024",
        ])
        .expect("parse");
        assert!(!cli.no_mitm);
        assert_eq!(cli.mitm_listen.port(), 4000);
        assert_eq!(cli.mitm_body_limit, 1024);
    }

    #[test]
    fn cli_default_mitm_body_limit_handles_agent_payloads() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");

        assert_eq!(cli.mitm_body_limit, 1_048_576);
        assert_eq!(cli.mitm_body_limit, cli.mitm_max_body_bytes);
    }

    #[test]
    fn cli_no_mitm_disables_mitm() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234", "--no-mitm"]).expect("parse");
        assert!(cli.no_mitm);
    }

    #[test]
    fn cli_system_proxy_is_opt_in() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");
        assert!(!cli.mitm_system_proxy);

        let result = Cli::try_parse_from(["etwarden", "--pid", "1234", "--mitm-system-proxy"]);
        assert!(result.is_err());

        let cli = Cli::try_parse_from([
            "etwarden",
            "--pid",
            "1234",
            "--no-divert",
            "--mitm-system-proxy",
        ])
        .expect("parse");
        assert!(cli.mitm_system_proxy);
        assert!(cli.no_divert);
    }

    #[test]
    fn cli_divert_is_explicit_opt_in() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");
        assert!(!cli.divert);

        let cli = Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert"]).expect("parse");
        assert!(cli.divert);

        let result = Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert", "--no-divert"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_parses_divert_port_filters() {
        let cli = Cli::try_parse_from([
            "etwarden",
            "--pid",
            "1234",
            "--divert",
            "--divert-ports",
            "80,443",
            "--divert-exclude-ports",
            "16669",
        ])
        .expect("parse");

        assert_eq!(cli.divert_ports, vec![80, 443]);
        assert_eq!(cli.divert_exclude_ports, vec![16669]);
    }

    #[test]
    fn cli_parses_divert_tls_mitm_opt_in() {
        let cli =
            Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert", "--divert-tls-mitm"])
                .expect("parse");

        assert!(cli.divert_tls_mitm);
        assert!(Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert-tls-mitm"]).is_err());
    }

    #[test]
    fn cli_default_duration_is_zero() {
        let cli = Cli::try_parse_from(["etwarden", "--pid", "1"]).expect("parse");
        assert_eq!(cli.duration, 0);
    }

    #[test]
    fn cli_rejects_invalid_args() {
        let result = Cli::try_parse_from(["etwarden", "--pid", "abc"]);
        assert!(result.is_err());

        let result = Cli::try_parse_from(["etwarden", "--pid", "1", "--json-pretty"]);
        assert!(result.is_err());
    }
}
