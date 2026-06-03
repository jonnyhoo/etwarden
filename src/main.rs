//! # `etwarden` (binary entry)
//!
//! **Purpose**: Parse CLI, assemble modules, run capture loop, print summary.
//! **Public API**: (binary entry, no pub symbols)
//! **Dependencies**: `target`, `cli`, `capture`, `filter`, `output`, `pcap`, `process`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 103 / 120

use std::{io::Write, sync::Arc};

mod target;

use clap::{error::ErrorKind, Parser};
use etwarden::{
    capture::{self, CaptureConfig},
    cli::Cli,
    filter::pid::PidFilter,
    output::{
        json::JsonEmitter,
        schema::{ErrorLine, OutputLine},
    },
    pcap::writer::PcapNgWriter,
    process::ProcessNameCache,
};

fn main() -> anyhow::Result<()> {
    match run() {
        Ok(()) => Ok(()),
        Err(err) => {
            let error_line = OutputLine::Error(ErrorLine::new(err.to_string()));
            if let Err(write_err) = write_output_line(&error_line) {
                eprintln!("[etwarden] failed to write NDJSON error line: {write_err}");
            }
            Err(err)
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = parse_cli()?;

    let target = target::resolve(&cli)?;
    let process_cache = Arc::new(ProcessNameCache::new());

    let mut config = CaptureConfig {
        target_pid: target.pid,
        duration: if cli.duration > 0 {
            Some(std::time::Duration::from_secs(cli.duration))
        } else {
            None
        },
        filters: vec![Box::new(PidFilter::single(target.pid))],
        emitter: Box::new(JsonEmitter::new(std::io::stdout()).with_process_cache(process_cache)),
        pcap_sink: cli
            .pcap_out
            .as_deref()
            .map(|p| {
                PcapNgWriter::create(std::path::Path::new(p))
                    .map(|w| Box::new(w) as Box<dyn etwarden::pcap::PcapSink>)
            })
            .transpose()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        stop_signal: Some(target.stop_signal),
    };

    let summary = capture::run_capture(&mut config).map_err(|e| anyhow::anyhow!("{e}"))?;

    write_output_line(&OutputLine::Summary(summary))?;

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
    let mut stderr = std::io::stderr().lock();
    if let Err(write_err) = stderr.write_all(err.to_string().as_bytes()) {
        eprintln!("[etwarden] failed to write CLI diagnostic: {write_err}");
    }
}

fn write_output_line(output: &OutputLine) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    write_output_line_to(&mut stdout, output)
}

fn write_output_line_to(writer: &mut dyn Write, output: &OutputLine) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, output)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_help_maps_to_error_line_message() {
        let err = Cli::try_parse_from(["etwarden", "--help"]).expect_err("help is intercepted");
        assert_eq!(cli_error_message(&err), "help requested");
    }

    #[test]
    fn output_error_line_is_ndjson() {
        let mut buf = Vec::new();
        let output = OutputLine::Error(ErrorLine::new("capture failed"));
        write_output_line_to(&mut buf, &output).expect("write");
        let line = String::from_utf8(buf).expect("utf8");
        assert_eq!(
            line,
            "{\"type\":\"error\",\"message\":\"capture failed\"}\n"
        );
    }
}
