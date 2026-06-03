//! # `etwarden` (binary entry)
//!
//! **Purpose**: Parse CLI, assemble modules, run capture loop, print summary.
//! **Public API**: (binary entry, no pub symbols)
//! **Dependencies**: `cli`, `capture`, `parser`, `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 60 / 80

use clap::Parser;
use etwarden::{
    capture::{self, CaptureConfig},
    cli::Cli,
    output::{json::JsonEmitter, schema::OutputLine},
    pcap::writer::PcapNgWriter,
    process::{spawn_and_get_pid, ProcessMonitor},
};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let (target_pid, _monitor) = resolve_target(&cli)?;

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
///
/// For `--pid`: returns the given PID directly.
/// For `--spawn`: spawns the command, returns its PID and a `ProcessMonitor`
/// for the caller to wait on.
fn resolve_target(cli: &Cli) -> anyhow::Result<(u32, Option<ProcessMonitor>)> {
    match (cli.pid, &cli.spawn) {
        (Some(pid), None) => Ok((pid, None)),
        (None, Some(cmd)) => {
            let result = spawn_and_get_pid(cmd).map_err(|e| anyhow::anyhow!("{e}"))?;
            let monitor = ProcessMonitor::new(result.child);
            eprintln!("[etwarden] spawned PID {}", monitor.pid());
            Ok((monitor.pid(), Some(monitor)))
        }
        (None, None) => {
            anyhow::bail!("specify --pid <PID> or --spawn <command>");
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("cannot specify both --pid and --spawn");
        }
    }
}
