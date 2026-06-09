//! # `app::tests`
//!
//! **Purpose**: Unit tests for binary app routing helpers.
//! **Public API**: test module only
//! **Dependencies**: `app`, `clap`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 42 / 80

use clap::Parser;

use super::*;

#[test]
fn cli_help_maps_to_error_line_message() {
    let err = Cli::try_parse_from(["etwarden", "--help"]).expect_err("help is intercepted");
    assert_eq!(cli_error_message(&err), "help requested");
}

#[test]
fn process_command_rejects_capture_flags() {
    let cli = Cli::try_parse_from(["etwarden", "--pid", "42", "process", "list"]).expect("parse");

    assert!(reject_capture_flags_for_process_command(&cli).is_err());
}

#[test]
fn process_command_allows_plain_process_subcommand() {
    let cli = Cli::try_parse_from(["etwarden", "process", "list"]).expect("parse");

    assert!(reject_capture_flags_for_process_command(&cli).is_ok());
}
