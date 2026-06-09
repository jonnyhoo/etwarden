//! # `error`
//!
//! **Purpose**: Unified error types for etwarden using `thiserror`.
//! **Public API**: `enum EtwardenError`, `type Result<T>`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 68 / 80

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

    /// Process inventory or termination failure.
    #[error("process control error: {0}")]
    ProcessControl(String),

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
mod tests;
