//! # `capture_command`
//!
//! **Purpose**: Binary-internal capture and browse command orchestration.
//! **Public API**: binary-internal `run`
//! **Dependencies**: `target`, `etwarden::capture`, `etwarden::mitm`, `etwarden::output`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin` for capture modes
//! **Line budget**: 157 / 200

use std::sync::Arc;

use etwarden::{
    capture::{self, CaptureConfig},
    cli::{Cli, TargetMode},
    mitm::{CertificateAuthorityConfig, MitmCaptureConfig},
    output::{json::JsonEmitter, schema::spawn_target_to_line},
    pcap::writer::PcapNgWriter,
    process::ProcessTreeCache,
    rules::{config::RulesConfig, ruleset::RuleSet},
    runtime::browse::{self},
};

use crate::{stdout, target};

pub(super) fn run(cli: &Cli) -> anyhow::Result<()> {
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
            url,
            browser.as_deref(),
            *headless,
            browser_path.as_ref(),
            *timeout,
            *after_load,
        );
    }

    let process_cache = Arc::new(ProcessTreeCache::new());
    let target = target::resolve(cli, process_cache.as_ref())?;
    if target.is_spawned {
        stdout::write_output_line(&spawn_target_to_line(
            target.root_pid,
            target.pid,
            &target.capture_pids,
            &target.network_pids,
        ))?;
    }

    let rule_set = load_rule_set(cli)?;
    let mitm = mitm_capture_config(cli);
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
    stdout::write_output_line(&etwarden::output::schema::OutputLine::Summary(summary))?;
    Ok(())
}

fn load_rule_set(cli: &Cli) -> anyhow::Result<Option<Arc<RuleSet>>> {
    let Some(path) = cli.rules.as_deref() else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read rules file {}: {e}", path.display()))?;
    let config: RulesConfig = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("failed to parse rules file {}: {e}", path.display()))?;
    let rule_set =
        RuleSet::build(&config).map_err(|e| anyhow::anyhow!("failed to build rules: {e}"))?;
    etwarden::output::diagnostic::warn(format_args!(
        "rules loaded: {} replace, {} intercept, {} hosts, {} http_block, {} websocket_block",
        rule_set.replace.len(),
        rule_set.intercept.len(),
        rule_set.hosts.len(),
        rule_set.http_block.len(),
        rule_set.websocket_block.len(),
    ));
    Ok(Some(Arc::new(rule_set)))
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

    let launched = browse::launch_browser(&config)?;
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

    browse::wait_and_cleanup(&launched, timeout, after_load, &stop);
    let summary = capture_handle
        .join()
        .map_err(|_| anyhow::anyhow!("capture thread panicked"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    stdout::write_output_line(&etwarden::output::schema::OutputLine::Summary(summary))?;
    Ok(())
}

#[cfg(test)]
mod tests;
