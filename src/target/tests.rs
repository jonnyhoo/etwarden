//! # `target::tests`
//!
//! **Purpose**: Unit tests for binary target resolution helpers.
//! **Public API**: test module only
//! **Dependencies**: `target`, `clap`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 100 / 130

use clap::Parser;

use super::{
    spawn::{primary_pid, should_wait_for_spawn_descendant, SpawnTarget},
    *,
};

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
    let cli =
        Cli::try_parse_from(["etwarden", "--pid", "42", "spawn", "cmd /C exit 0"]).expect("parse");
    assert!(target_spec(&cli).is_err());
}

#[test]
fn target_spec_rejects_zero_pid_flag() {
    let cli = Cli::try_parse_from(["etwarden", "--pid", "0"]).expect("parse");
    assert!(target_spec(&cli).is_err());
}

#[test]
fn target_spec_rejects_zero_pid_subcommand() {
    let cli = Cli::try_parse_from(["etwarden", "pid", "0"]).expect("parse");
    assert!(target_spec(&cli).is_err());
}

#[test]
fn target_spec_passes_spawn_output_paths() {
    let cli = Cli::try_parse_from([
        "etwarden",
        "--spawn",
        "cmd /C exit 0",
        "--spawn-stdout",
        "result.json",
        "--spawn-stderr",
        "result.err",
    ])
    .expect("parse");
    let TargetSpec::Spawn(spec) = target_spec(&cli).expect("target") else {
        unreachable!("expected spawn target");
    };

    assert_eq!(spec.cmd, "cmd /C exit 0");
    assert_eq!(spec.options.stdout_path, Some("result.json".into()));
    assert_eq!(spec.options.stderr_path, Some("result.err".into()));
}

#[test]
fn target_spec_rejects_spawn_output_paths_for_pid_target() {
    let cli = Cli::try_parse_from(["etwarden", "--pid", "42", "--spawn-stdout", "result.json"])
        .expect("parse");

    assert!(
        matches!(target_spec(&cli), Err(err) if err.to_string().contains("require a spawn target"))
    );
}

#[test]
fn primary_pid_prefers_lowest_network_pid() {
    assert_eq!(
        primary_pid(10, &HashSet::from([10, 20, 30]), &HashSet::from([30, 20])),
        20
    );
}

#[test]
fn primary_pid_uses_descendant_when_network_owner_is_unknown() {
    assert_eq!(
        primary_pid(10, &HashSet::from([10, 20]), &HashSet::new()),
        20
    );
}

#[test]
fn primary_pid_falls_back_to_root_when_no_descendant_exists() {
    assert_eq!(primary_pid(10, &HashSet::from([10]), &HashSet::new()), 10);
}

#[test]
fn discovered_spawn_target_uses_tree_pids_and_network_primary() {
    let target =
        SpawnTarget::from_discovered(10, HashSet::from([10, 20, 30]), &HashSet::from([30]));

    assert_eq!(target.root_pid, 10);
    assert_eq!(target.pid, 30);
    assert_eq!(target.capture_pids, HashSet::from([10, 20, 30]));
}

#[test]
fn waits_for_wrapper_commands() {
    assert!(should_wait_for_spawn_descendant("cmd /C claude -p test"));
    assert!(should_wait_for_spawn_descendant(
        r#""C:\tools\claude.cmd" -p test"#
    ));
    assert!(should_wait_for_spawn_descendant(
        "pwsh -NoProfile -File script.ps1"
    ));
    assert!(!should_wait_for_spawn_descendant(
        "curl.exe https://example.com"
    ));
}
