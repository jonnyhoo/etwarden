//! # `cli::root`
//!
//! **Purpose**: Root CLI flags shared by capture and process commands.
//! **Public API**: `struct Cli`
//! **Dependencies**: `cli::target`, `clap`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 90 / 120

use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

use super::TargetMode;

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

    /// Keep `WinDivert` TCP redirect disabled.
    #[arg(long)]
    pub no_divert: bool,

    /// Path to a JSON rules file (replace/intercept/hosts/block rules).
    #[arg(long)]
    pub rules: Option<PathBuf>,
}
