//! # `error`
//!
//! **Purpose**: Unified error types for etwarden using `thiserror`.
//! **Public API**: `enum EtwardenError`, `type Result<T>`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 46 / 80

/// Unified error type for all etwarden operations.
#[derive(Debug, thiserror::Error)]
pub enum EtwardenError {
    /// ETW session creation, start, or stop failure.
    #[error("ETW session error: {0}")]
    EtwSession(String),

    /// Insufficient privileges (requires administrator).
    #[error("privilege error: {0}")]
    Privilege(String),

    /// Child process spawn or lifecycle failure.
    #[error("process spawn error: {0}")]
    ProcessSpawn(String),

    /// OS socket inventory read failure.
    #[error("network inventory error: {0}")]
    NetworkInventory(String),

    /// pcapng file write failure.
    #[error("pcap write error: {0}")]
    PcapWrite(String),

    /// Output serialization or write failure.
    #[error("output write error: {0}")]
    OutputWrite(String),

    /// HTTPS MITM proxy startup, runtime, or system-proxy failure.
    #[error("MITM proxy error: {0}")]
    MitmProxy(String),

    /// `WinDivert` packet interception failure.
    #[error("WinDivert error: {0}")]
    Divert(String),
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, EtwardenError>;

impl EtwardenError {
    /// Returns true if this error is due to insufficient privileges.
    ///
    /// # Returns
    /// `true` if the error variant is [`EtwardenError::Privilege`].
    #[must_use]
    pub const fn is_privilege(&self) -> bool {
        matches!(self, Self::Privilege(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etw_session_variant_displays_message() {
        let err = EtwardenError::EtwSession("start failed".into());
        let msg = err.to_string();
        assert!(msg.contains("ETW session error"), "actual: {msg}");
        assert!(msg.contains("start failed"), "actual: {msg}");
    }

    #[test]
    fn privilege_variant_is_privilege() {
        let err = EtwardenError::Privilege("not admin".into());
        assert!(err.is_privilege());
    }

    #[test]
    fn non_privilege_is_not_privilege() {
        let err = EtwardenError::OutputWrite("disk full".into());
        assert!(!err.is_privilege());
    }

    #[test]
    fn process_spawn_variant_displays_message() {
        let err = EtwardenError::ProcessSpawn("not found".into());
        let msg = err.to_string();
        assert!(msg.contains("process spawn error"), "actual: {msg}");
    }

    #[test]
    fn network_inventory_variant_displays_message() {
        let err = EtwardenError::NetworkInventory("socket table unavailable".into());
        let msg = err.to_string();
        assert!(msg.contains("network inventory error"), "actual: {msg}");
    }

    #[test]
    fn pcap_write_variant_displays_message() {
        let err = EtwardenError::PcapWrite("io error".into());
        let msg = err.to_string();
        assert!(msg.contains("pcap write error"), "actual: {msg}");
    }

    #[test]
    fn output_write_variant_displays_message() {
        let err = EtwardenError::OutputWrite("pipe closed".into());
        let msg = err.to_string();
        assert!(msg.contains("output write error"), "actual: {msg}");
    }

    #[test]
    fn mitm_proxy_variant_displays_message() {
        let err = EtwardenError::MitmProxy("bind failed".into());
        let msg = err.to_string();
        assert!(msg.contains("MITM proxy error"), "actual: {msg}");
    }

    #[test]
    fn result_alias_works() {
        fn returns_result() -> Result<()> {
            Err(EtwardenError::EtwSession("test".into()))
        }
        let res = returns_result();
        assert!(res.is_err());
    }
}
