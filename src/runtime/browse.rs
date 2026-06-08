//! # `runtime::browse`
//!
//! **Purpose**: Browse subcommand lifecycle — discover browser, launch headless,
//! wait for page load via CDP, cleanup via Job Object.
//! **Public API**: `struct BrowseConfig`, `struct LaunchedBrowser`,
//! `fn launch_browser`, `fn wait_and_cleanup`
//! **Dependencies**: `runtime::which`, `runtime::cdp`, `output`, `process::job`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 210 / 240

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{process::JobObject, runtime::which::BrowserFamily};

/// Configuration for the browse subcommand.
pub struct BrowseConfig {
    /// URL to navigate to.
    pub url: String,
    /// Preferred browser family.
    pub browser: Option<BrowserFamily>,
    /// Run in headless mode.
    pub headless: bool,
    /// Explicit browser executable path (overrides discovery).
    pub browser_path: Option<PathBuf>,
    /// Maximum time to wait for page load in seconds.
    pub timeout_secs: u64,
    /// Capture duration after page load in seconds. 0 = stop immediately after load.
    pub duration_after_load: u64,
}

/// A launched browser process awaiting CDP connection.
pub struct LaunchedBrowser {
    /// PID of the browser process.
    pub pid: u32,
    /// Remote debugging port.
    pub debug_port: u16,
    /// Temp user-data-dir (Chrome 136+ requires non-default data dir for CDP).
    pub user_data_dir: PathBuf,
    /// Job Object that kills the browser tree on drop.
    job: JobObject,
}

/// Discovers and launches a browser with remote debugging enabled.
///
/// # Errors
/// Returns an error if browser discovery or process launch fails.
pub fn launch_browser(config: &BrowseConfig) -> anyhow::Result<LaunchedBrowser> {
    // 1. Discover browser
    let browser = match &config.browser_path {
        Some(path) => crate::runtime::which::BrowserCandidate {
            path: path.clone(),
            family: config.browser.unwrap_or(BrowserFamily::Chrome),
            source: "explicit",
        },
        None => crate::runtime::which::find_browser(config.browser)
            .ok_or_else(|| anyhow::anyhow!("no browser found. Install Chrome or Edge."))?,
    };

    crate::output::diagnostic::warn(format_args!(
        "using browser: {} ({})",
        browser.path.display(),
        browser.source
    ));

    // 2. Pick a free port for remote debugging
    let debug_port = pick_free_port();

    // 3. Create temp user-data-dir (Chrome 136+ requires non-default for CDP)
    let user_data_dir = std::env::temp_dir().join(format!("etwarden-cdp-{debug_port}"));
    std::fs::create_dir_all(&user_data_dir)?;

    // 4. Create Job Object for browser process tree lifecycle
    let job = JobObject::new().map_err(|e| anyhow::anyhow!("{e}"))?;

    // 5. Launch browser
    let mut cmd = std::process::Command::new(&browser.path);
    cmd.arg(format!("--remote-debugging-port={debug_port}"))
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-background-networking")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Edge/Chrome need CREATE_NO_WINDOW to properly open CDP port when launched from console
    #[cfg(target_os = "windows")]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0800_0000);

    if config.headless {
        cmd.arg("--headless=new");
    }

    cmd.arg(&config.url);

    let child = cmd.spawn().map_err(|e| {
        anyhow::anyhow!("failed to launch browser '{}': {e}", browser.path.display())
    })?;
    let pid = child.id();

    // 6. Assign browser process to Job Object
    job.assign_pid(pid).map_err(|e| {
        crate::output::diagnostic::warn(format_args!(
            "job assign failed for browser PID {pid}: {e}"
        ));
        anyhow::anyhow!("{e}")
    })?;

    crate::output::diagnostic::warn(format_args!(
        "launched browser PID {pid} on debug port {debug_port}, user-data-dir={} (job-assigned)",
        user_data_dir.display()
    ));

    // Drop child handle — lifecycle managed by Job Object
    drop(child);

    Ok(LaunchedBrowser {
        pid,
        debug_port,
        user_data_dir,
        job,
    })
}

/// Waits for CDP page load, then waits for additional capture duration, then kills browser.
///
/// # Returns
/// `true` if page load was detected via CDP, `false` otherwise.
pub fn wait_and_cleanup(
    launched: &LaunchedBrowser,
    timeout_secs: u64,
    duration_after_load: u64,
    stop: &Arc<AtomicBool>,
) -> bool {
    // 1. Wait for CDP page load
    let page_loaded = match wait_for_cdp_page_load(
        launched.debug_port,
        &launched.user_data_dir,
        timeout_secs,
        stop,
    ) {
        Ok(()) => {
            crate::output::diagnostic::warn(format_args!("page load detected via CDP"));
            true
        }
        Err(e) => {
            crate::output::diagnostic::warn(format_args!("CDP page load wait failed: {e}"));
            false
        }
    };

    // 2. Wait for additional capture duration after page load
    if page_loaded && duration_after_load > 0 {
        let remaining = Duration::from_secs(duration_after_load);
        crate::output::diagnostic::warn(format_args!(
            "capturing for {duration_after_load} more seconds after page load"
        ));
        let start = std::time::Instant::now();
        while !stop.load(Ordering::Relaxed) && start.elapsed() < remaining {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // 3. Signal stop
    stop.store(true, Ordering::Relaxed);

    // 4. Kill browser process tree via Job Object
    if let Err(e) = launched.job.terminate(1) {
        crate::output::diagnostic::warn(format_args!("job terminate failed: {e}"));
    }

    // 5. Clean up temp user-data-dir
    let _ = std::fs::remove_dir_all(&launched.user_data_dir);

    crate::output::diagnostic::warn(format_args!(
        "browse session complete for PID {}",
        launched.pid
    ));

    page_loaded
}

/// Picks a free TCP port by binding to port 0.
fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr().map(|addr| addr.port()))
        .unwrap_or(9222)
}

/// Waits for CDP to become available, then waits for page load event.
///
/// HTTP discovery runs synchronously (blocking TCP works reliably on main thread).
/// Only the WebSocket connection uses tokio.
fn wait_for_cdp_page_load(
    port: u16,
    _user_data_dir: &Path,
    timeout_secs: u64,
    stop: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

    // Give Edge time to open the CDP port before first attempt
    std::thread::sleep(Duration::from_secs(2));

    loop {
        if stop.load(Ordering::Relaxed) {
            anyhow::bail!("stopped before CDP connected");
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("timeout waiting for CDP at port {port}");
        }

        // Synchronous HTTP GET to /json (works reliably on main thread)
        match crate::runtime::cdp::http_get_json(port) {
            Ok(body) => {
                if let Some(ws_url) = crate::runtime::cdp::parse_page_ws_from_json(&body) {
                    crate::output::diagnostic::warn(format_args!("CDP discovered WS: {ws_url}"));
                    // WebSocket connection via tokio (only async part)
                    return crate::runtime::cdp::wait_for_page_load_via_ws(&ws_url, remaining);
                }
                crate::output::diagnostic::warn(format_args!(
                    "CDP /json returned {} bytes but no page WS URL",
                    body.len()
                ));
            }
            Err(e) => {
                crate::output::diagnostic::warn(format_args!("CDP /json attempt failed: {e}"));
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}
