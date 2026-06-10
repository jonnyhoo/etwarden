//! # `capture_command::tests`
//!
//! **Purpose**: Unit tests for capture command helpers.
//! **Public API**: test module only
//! **Dependencies**: `capture_command`, `clap`, `etwarden::rules`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 59 / 80

use clap::Parser;

use super::*;

#[test]
fn mitm_capture_config_disables_system_proxy_by_default() {
    let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");
    let config = mitm_capture_config(&cli).expect("mitm config");

    assert!(!config.enable_system_proxy);
}

#[test]
fn mitm_capture_config_limits_system_proxy_to_legacy_no_divert_mode() {
    let cli = Cli::try_parse_from([
        "etwarden",
        "--pid",
        "1234",
        "--mitm-system-proxy",
        "--no-divert",
    ])
    .expect("parse");
    let config = mitm_capture_config(&cli).expect("mitm config");

    assert!(config.enable_system_proxy);
}

#[test]
fn divert_requires_explicit_opt_in() {
    let cli = Cli::try_parse_from(["etwarden", "--pid", "1234"]).expect("parse");
    assert!(!cli.divert);

    let cli = Cli::try_parse_from(["etwarden", "--pid", "1234", "--divert"]).expect("parse");
    assert!(cli.divert);
}

#[test]
fn rules_loaded_message_reports_socket_block_counts() {
    let config: RulesConfig = serde_json::from_str(
        r#"{"block_rules":{"tcp":[{"enable":true,"priority":1,"address":"10.0.0.7:443","action":"Disconnect"}],"udp":[{"enable":true,"priority":1,"address":"8.8.8.8:53","action":"DropUpstream"}]}}"#,
    )
    .expect("parse rules config");
    let rule_set = RuleSet::build(&config).expect("build rule set");

    let message = rules_loaded_message(&rule_set);

    assert!(message.contains("1 tcp_block"));
    assert!(message.contains("1 udp_block"));
}
