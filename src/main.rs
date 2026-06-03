//! # `etwarden` (binary entry)
//!
//! **Purpose**: Parse CLI, assemble modules, run capture loop, print summary.
//! **Public API**: (binary entry, no pub symbols)
//! **Dependencies**: `cli`, `capture`, `parser`, `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 44 / 80

use clap::Parser;
use etwarden::{
    capture::{self, CaptureConfig},
    cli::Cli,
    output::{json::JsonEmitter, schema::OutputLine},
    pcap::writer::PcapNgWriter,
};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let target_pid = resolve_target_pid(&cli)?;

    let mut config = CaptureConfig {
        target_pid,
        duration: if cli.duration > 0 {
            Some(std::time::Duration::from_secs(cli.duration))
        } else {
            None
        },
        filters: Vec::new(),
        emitter: Box::new(JsonEmitter::new(std::io::stdout())),
        pcap_sink: cli
            .pcap_out
            .as_deref()
            .map(|p| {
                PcapNgWriter::create(std::path::Path::new(p))
                    .map(|w| Box::new(w) as Box<dyn etwarden::pcap::PcapSink>)
            })
            .transpose()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    };

    let summary = capture::run_capture(&mut config).map_err(|e| anyhow::anyhow!("{e}"))?;

    let output = OutputLine::Summary(summary);
    let json = serde_json::to_string(&output)?;
    println!("{json}");

    Ok(())
}

/// Resolves the target PID from CLI arguments.
fn resolve_target_pid(cli: &Cli) -> anyhow::Result<u32> {
    match (cli.pid, &cli.spawn) {
        (Some(pid), None) => Ok(pid),
        (None, Some(_cmd)) => {
            // T31 will implement spawn mode
            anyhow::bail!("--spawn mode not yet implemented");
        }
        (None, None) => {
            anyhow::bail!("specify --pid <PID> or --spawn <command>");
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("cannot specify both --pid and --spawn");
        }
    }
}
