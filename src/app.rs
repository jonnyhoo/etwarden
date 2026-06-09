//! # `app`
//!
//! **Purpose**: Parse CLI and route command families.
//! **Public API**: binary-internal `main_entry`
//! **Dependencies**: `capture_command`, `process_command`, `stdout`, `cli`, `output`
//! **Platform**: `windows-only`
//! **Privilege**: command-dependent
//! **Line budget**: 73 / 100

use clap::{error::ErrorKind, Parser};
use etwarden::{
    cli::{Cli, TargetMode},
    output::{
        diagnostic,
        schema::{ErrorLine, OutputLine},
    },
};

use crate::{capture_command, process_command, stdout};

pub(super) fn main_entry() -> anyhow::Result<()> {
    match run() {
        Ok(()) => Ok(()),
        Err(err) => {
            let error_line = OutputLine::Error(ErrorLine::new(err.to_string()));
            if let Err(write_err) = stdout::write_output_line(&error_line) {
                diagnostic::warn(format_args!(
                    "failed to write NDJSON error line: {write_err}"
                ));
            }
            Err(err)
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = parse_cli()?;
    if let Some(TargetMode::Process { command }) = &cli.target {
        reject_capture_flags_for_process_command(&cli)?;
        for line in process_command::lines(command)? {
            stdout::write_output_line(&line)?;
        }
        return Ok(());
    }

    capture_command::run(&cli)
}

fn reject_capture_flags_for_process_command(cli: &Cli) -> anyhow::Result<()> {
    if cli.pid.is_some()
        || cli.spawn.is_some()
        || cli.spawn_stdout.is_some()
        || cli.spawn_stderr.is_some()
        || cli.pcap_out.is_some()
        || cli.rules.is_some()
    {
        anyhow::bail!("process subcommands cannot be combined with capture target flags");
    }
    Ok(())
}

fn parse_cli() -> anyhow::Result<Cli> {
    Cli::try_parse().map_err(|err| {
        write_cli_diagnostic(&err);
        anyhow::anyhow!(cli_error_message(&err))
    })
}

fn cli_error_message(err: &clap::Error) -> String {
    match err.kind() {
        ErrorKind::DisplayHelp => "help requested".into(),
        ErrorKind::DisplayVersion => "version requested".into(),
        _ => err
            .to_string()
            .lines()
            .next()
            .unwrap_or("CLI parse error")
            .to_string(),
    }
}

fn write_cli_diagnostic(err: &clap::Error) {
    if let Err(write_err) = diagnostic::write(format_args!("{err}")) {
        diagnostic::warn(format_args!("failed to write CLI diagnostic: {write_err}"));
    }
}

#[cfg(test)]
mod tests;
