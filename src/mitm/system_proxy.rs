//! # `mitm::system_proxy`
//!
//! **Purpose**: Opt-in system proxy mutation with best-effort restoration.
//! **Public API**: `SystemProxyGuard`
//! **Dependencies**: `std::process`, `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `user-registry-write`
//! **Line budget**: 196 / 200

use std::{net::SocketAddr, process::Command};

use crate::{
    error::{EtwardenError, Result},
    output::diagnostic,
};

const INTERNET_SETTINGS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

enum RegistryValue {
    Dword(String),
    Sz(String),
    Missing,
}

struct ProxySetting {
    enable: RegistryValue,
    server: RegistryValue,
    override_list: RegistryValue,
}

/// Restores the previous system proxy when explicitly stopped or dropped.
pub struct SystemProxyGuard {
    previous: Option<ProxySetting>,
}

impl SystemProxyGuard {
    /// Enables the OS-level proxy and stores previous settings for restoration.
    ///
    /// # Arguments
    /// * `addr` — Local MITM proxy listen address to publish as `ProxyServer`.
    ///
    /// # Returns
    /// Guard that restores previous proxy settings on `restore` or `drop`.
    ///
    /// # Errors
    /// Returns `Err` when `reg.exe` cannot read or write HKCU internet settings.
    pub fn enable(addr: SocketAddr) -> Result<Self> {
        let previous = ProxySetting::read()?;
        let next = ProxySetting {
            enable: RegistryValue::Dword("1".into()),
            server: RegistryValue::Sz(addr.to_string()),
            override_list: RegistryValue::Sz("localhost;127.*;[::1]".into()),
        };
        next.write()?;

        Ok(Self {
            previous: Some(previous),
        })
    }

    /// Restores the previous system proxy settings once.
    ///
    /// # Returns
    /// `Ok(())` when settings were restored or already restored.
    ///
    /// # Errors
    /// Returns `Err` when `reg.exe` cannot restore an HKCU internet setting.
    pub fn restore(&mut self) -> Result<()> {
        let Some(previous) = self.previous.take() else {
            return Ok(());
        };
        previous.write()
    }
}

impl ProxySetting {
    fn read() -> Result<Self> {
        Ok(Self {
            enable: query_value("ProxyEnable")?,
            server: query_value("ProxyServer")?,
            override_list: query_value("ProxyOverride")?,
        })
    }

    fn write(&self) -> Result<()> {
        set_value("ProxyEnable", &self.enable)?;
        set_value("ProxyServer", &self.server)?;
        set_value("ProxyOverride", &self.override_list)
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        if let Err(err) = self.restore() {
            diagnostic::warn(format_args!("{err}"));
        }
    }
}

fn query_value(name: &str) -> Result<RegistryValue> {
    let output = Command::new("reg")
        .args(["query", INTERNET_SETTINGS_KEY, "/v", name])
        .output()
        .map_err(|err| EtwardenError::MitmProxy(format!("failed to run reg.exe: {err}")))?;
    if !output.status.success() {
        return Ok(RegistryValue::Missing);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_query_output(&stdout, name)
}

fn parse_query_output(output: &str, name: &str) -> Result<RegistryValue> {
    for line in output.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(name) else {
            continue;
        };
        if !rest.chars().next().is_some_and(char::is_whitespace) {
            continue;
        }
        let Some((kind, data)) = split_token(rest.trim_start()) else {
            continue;
        };
        return match kind {
            "REG_DWORD" => Ok(RegistryValue::Dword(data.to_owned())),
            "REG_SZ" => Ok(RegistryValue::Sz(data.to_owned())),
            other => Err(EtwardenError::MitmProxy(format!(
                "unsupported registry type for {name}: {other}"
            ))),
        };
    }
    Err(EtwardenError::MitmProxy(format!(
        "failed to parse registry value {name}"
    )))
}

fn split_token(input: &str) -> Option<(&str, &str)> {
    let index = input.find(char::is_whitespace)?;
    let token = &input[..index];
    let rest = input[index..].trim_start();
    Some((token, rest))
}

fn set_value(name: &str, value: &RegistryValue) -> Result<()> {
    match value {
        RegistryValue::Dword(data) => run_reg(&[
            "add",
            INTERNET_SETTINGS_KEY,
            "/v",
            name,
            "/t",
            "REG_DWORD",
            "/d",
            data,
            "/f",
        ]),
        RegistryValue::Sz(data) => run_reg(&[
            "add",
            INTERNET_SETTINGS_KEY,
            "/v",
            name,
            "/t",
            "REG_SZ",
            "/d",
            data,
            "/f",
        ]),
        RegistryValue::Missing => run_reg(&["delete", INTERNET_SETTINGS_KEY, "/v", name, "/f"]),
    }
}

fn run_reg(args: &[&str]) -> Result<()> {
    let output = Command::new("reg")
        .args(args)
        .output()
        .map_err(|err| EtwardenError::MitmProxy(format!("failed to run reg.exe: {err}")))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim();
    if args.first().is_some_and(|arg| *arg == "delete")
        && message.contains("unable to find the specified registry key or value")
    {
        return Ok(());
    }
    let detail = if message.is_empty() {
        format!("reg.exe {} failed", args.join(" "))
    } else {
        format!("reg.exe {} failed: {message}", args.join(" "))
    };
    Err(EtwardenError::MitmProxy(detail))
}
