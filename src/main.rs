//! # `etwarden` (binary entry)
//!
//! **Purpose**: Parse CLI, assemble modules, run capture loop, print summary.
//! **Public API**: (binary entry, no pub symbols)
//! **Dependencies**: `target`, `cli`, `capture`, `filter`, `output`, `pcap`, `process`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 59 / 80

use std::{io::Write, sync::Arc};

mod target;

use clap::Parser;
use etwarden::{
    capture::{self, CaptureConfig},
    cli::Cli,
    filter::pid::PidFilter,
    output::{json::JsonEmitter, schema::OutputLine},
    pcap::writer::PcapNgWriter,
    process::ProcessNameCache,
};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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

    let output = OutputLine::Summary(summary);
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &output)?;
    stdout.write_all(b"\n")?;

    Ok(())
}
