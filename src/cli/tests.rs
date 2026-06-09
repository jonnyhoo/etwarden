//! # `cli::tests`
//!
//! **Purpose**: Unit tests for command-line parsing.
//! **Public API**: test module only
//! **Dependencies**: `cli`, `clap`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 126 / 160

use std::path::PathBuf;

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
}

#[test]
fn cli_divert_is_explicit_opt_in() {
    let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");
    assert!(!cli.divert);

    let cli = Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert"]).expect("parse");
    assert!(cli.divert);
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
    let cli = Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert", "--divert-tls-mitm"])
        .expect("parse");

    assert!(cli.divert_tls_mitm);
    assert!(Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert-tls-mitm"]).is_err());
}

#[test]
fn cli_parses_process_commands() {
    let cli =
        Cli::try_parse_from(["etwarden", "process", "list", "--filter", "claude"]).expect("parse");
    let Some(TargetMode::Process {
        command: ProcessCommand::List { filter, .. },
    }) = cli.target
    else {
        unreachable!("expected process list");
    };
    assert_eq!(filter.as_deref(), Some("claude"));

    let cli = Cli::try_parse_from(["etwarden", "process", "kill", "--pid", "42", "--force"])
        .expect("parse");
    let Some(TargetMode::Process {
        command: ProcessCommand::Kill { pid, force, .. },
    }) = cli.target
    else {
        unreachable!("expected process kill");
    };
    assert_eq!(pid, 42);
    assert!(force);
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
