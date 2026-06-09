//! # `etwarden` (binary entry)
//!
//! **Purpose**: Parse CLI, assemble modules, run capture loop, print summary.
//! **Public API**: (binary entry, no pub symbols)
//! **Dependencies**: `target`, `cli`, `capture`, `filter`, `output`, `pcap`, `process`, `runtime`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 173 / 190

use std::{io::Write, sync::Arc};

mod target;

use clap::{error::ErrorKind, Parser};
use etwarden::{
    capture::{self, CaptureConfig},
    cli::{Cli, TargetMode},
    mitm::{CertificateAuthorityConfig, MitmCaptureConfig},
    output::{
        diagnostic,
        json::JsonEmitter,
        schema::{ErrorLine, OutputLine},
    },
    pcap::writer::PcapNgWriter,
    process::ProcessTreeCache,
    rules::{config::RulesConfig, ruleset::RuleSet},
    runtime::browse::{self},
};

fn main() -> anyhow::Result<()> {
    match run() {
        Ok(()) => Ok(()),
        Err(err) => {
            let error_line = OutputLine::Error(ErrorLine::new(err.to_string()));
            if let Err(write_err) = write_output_line(&error_line) {
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

    // Browse mode: separate lifecycle from Pid/Spawn
    if let Some(TargetMode::Browse {
        url,
        browser,
        headless,
        browser_path,
        timeout,
        after_load,
    }) = &cli.target
    {
        return run_browse_mode(
            &cli,
            url,
            browser.as_deref(),
            *headless,
            browser_path.as_ref(),
            *timeout,
            *after_load,
        );
    }

    let process_cache = Arc::new(ProcessTreeCache::new());
    let target = target::resolve(&cli, process_cache.as_ref())?;

    let rule_set = load_rule_set(&cli)?;
    let mitm = mitm_capture_config(&cli);
    let enable_divert = mitm.is_some() && cli.divert;

    let mut config = CaptureConfig {
        target_pid: target.pid,
        capture_pids: target.capture_pids.clone(),
        duration: if cli.duration > 0 {
            Some(std::time::Duration::from_secs(cli.duration))
        } else {
            None
        },
        filters: target::filters(&target, Arc::clone(&process_cache)),
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
        mitm,
        stop_signal: Some(target.stop_signal),
        rule_set,
        enable_divert,
        divert_ports: cli.divert_ports.clone(),
        divert_exclude_ports: cli.divert_exclude_ports.clone(),
    };

    let summary = capture::run_capture(&mut config).map_err(|e| anyhow::anyhow!("{e}"))?;

    write_output_line(&OutputLine::Summary(summary))?;

    Ok(())
}

fn load_rule_set(cli: &Cli) -> anyhow::Result<Option<std::sync::Arc<RuleSet>>> {
    let Some(path) = cli.rules.as_deref() else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read rules file {}: {e}", path.display()))?;
    let config: RulesConfig = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("failed to parse rules file {}: {e}", path.display()))?;
    let rule_set =
        RuleSet::build(&config).map_err(|e| anyhow::anyhow!("failed to build rules: {e}"))?;
    diagnostic::warn(format_args!(
        "rules loaded: {} replace, {} intercept, {} hosts, {} http_block, {} websocket_block",
        rule_set.replace.len(),
        rule_set.intercept.len(),
        rule_set.hosts.len(),
        rule_set.http_block.len(),
        rule_set.websocket_block.len(),
    ));
    Ok(Some(std::sync::Arc::new(rule_set)))
}

fn mitm_capture_config(cli: &Cli) -> Option<MitmCaptureConfig> {
    if cli.no_mitm {
        return None;
    }
    Some(MitmCaptureConfig {
        listen_addr: cli.mitm_listen,
        ca: CertificateAuthorityConfig {
            cert_path: cli.mitm_ca_cert.clone(),
            key_path: cli.mitm_ca_key.clone(),
        },
        body_limit: cli.mitm_body_limit,
        max_body_bytes: cli.mitm_max_body_bytes,
        enable_system_proxy: cli.mitm_system_proxy && cli.no_divert,
        divert_tls_mitm: cli.divert_tls_mitm,
    })
}

fn run_browse_mode(
    _cli: &Cli,
    url: &str,
    browser: Option<&str>,
    headless: bool,
    browser_path: Option<&std::path::PathBuf>,
    timeout: u64,
    after_load: u64,
) -> anyhow::Result<()> {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let process_cache = Arc::new(ProcessTreeCache::new());
    let browser_family = browser.and_then(etwarden::runtime::which::parse_browser_family);

    let config = browse::BrowseConfig {
        url: url.to_string(),
        browser: browser_family,
        headless,
        browser_path: browser_path.cloned(),
        timeout_secs: timeout,
        duration_after_load: after_load,
    };

    // 1. Launch browser (returns immediately)
    let launched = browse::launch_browser(&config)?;

    // 2. Start ETW capture in a background thread
    let capture_stop = Arc::clone(&stop);
    let capture_pids = std::collections::HashSet::from([launched.pid]);
    let emitter = Box::new(
        JsonEmitter::new(std::io::stdout()).with_process_cache(Arc::clone(&process_cache)),
    );
    let tree_filter_root = launched.pid;
    let tree_filter_cache = Arc::clone(&process_cache);
    let capture_handle = std::thread::spawn(move || {
        let mut capture_config = CaptureConfig {
            target_pid: tree_filter_root,
            capture_pids,
            duration: None,
            filters: vec![Box::new(etwarden::filter::tree::ProcessTreeFilter::new(
                tree_filter_root,
                tree_filter_cache,
                [],
            ))],
            emitter,
            pcap_sink: None,
            mitm: None,
            stop_signal: Some(capture_stop),
            rule_set: None,
            enable_divert: false,
            divert_ports: Vec::new(),
            divert_exclude_ports: Vec::new(),
        };
        capture::run_capture(&mut capture_config)
    });

    // 3. Wait for CDP page load + after_load duration, then kill browser
    browse::wait_and_cleanup(&launched, timeout, after_load, &stop);

    // 4. Collect capture result
    let summary = capture_handle
        .join()
        .map_err(|_| anyhow::anyhow!("capture thread panicked"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
    if let Err(write_err) = diagnostic::write(format_args!("{err}")) {
        diagnostic::warn(format_args!("failed to write CLI diagnostic: {write_err}"));
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
}
