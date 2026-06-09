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
