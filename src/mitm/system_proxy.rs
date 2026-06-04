//! # `mitm::system_proxy`
//!
//! **Purpose**: Opt-in system proxy mutation with best-effort restoration.
//! **Public API**: `SystemProxyGuard`
//! **Dependencies**: `sysproxy`, `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `user-registry-write`
//! **Line budget**: 95 / 140

use std::net::SocketAddr;

use crate::{
    error::{EtwardenError, Result},
    output::diagnostic,
};

/// Restores the previous system proxy when explicitly stopped or dropped.
pub struct SystemProxyGuard {
    previous: Option<sysproxy::Sysproxy>,
}

impl SystemProxyGuard {
    /// Enables the OS-level proxy and stores previous settings for restoration.
    pub fn enable(addr: SocketAddr) -> Result<Self> {
        if !sysproxy::Sysproxy::is_support() {
            return Err(EtwardenError::MitmProxy(
                "system proxy is unsupported on this platform".into(),
            ));
        }

        let previous = sysproxy::Sysproxy::get_system_proxy().map_err(|e| {
            EtwardenError::MitmProxy(format!("failed to read current system proxy: {e}"))
        })?;
        let next = sysproxy::Sysproxy {
            enable: true,
            host: addr.ip().to_string(),
            port: addr.port(),
            bypass: "localhost;127.*;[::1]".into(),
        };
        next.set_system_proxy().map_err(|e| {
            EtwardenError::MitmProxy(format!("failed to enable system proxy {addr}: {e}"))
        })?;

        Ok(Self {
            previous: Some(previous),
        })
    }

    /// Restores the previous system proxy settings once.
    pub fn restore(&mut self) -> Result<()> {
        let Some(previous) = self.previous.take() else {
            return Ok(());
        };
        previous
            .set_system_proxy()
            .map_err(|e| EtwardenError::MitmProxy(format!("failed to restore system proxy: {e}")))
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        if let Err(err) = self.restore() {
            diagnostic::warn(format_args!("{err}"));
        }
    }
}
