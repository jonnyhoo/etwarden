//! # `parser::types::event::accessors`
//!
//! **Purpose**: Implements common `NetEvent` field accessors.
//! **Public API**: inherent `NetEvent` accessors
//! **Dependencies**: `parser::types::event`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 52 / 80

use super::NetEvent;

impl NetEvent {
    /// Returns the `bytes_out` field from any variant.
    #[must_use]
    pub const fn bytes_out(&self) -> u64 {
        match self {
            Self::Connect { bytes_out, .. }
            | Self::Disconnect { bytes_out, .. }
            | Self::Send { bytes_out, .. }
            | Self::Recv { bytes_out, .. } => *bytes_out,
            Self::RawCapture { .. }
            | Self::DnsQuery { .. }
            | Self::DnsResponse { .. }
            | Self::HttpRequest { .. }
            | Self::DecryptedHttpRequest { .. }
            | Self::HttpResponse { .. }
            | Self::DecryptedHttpResponse { .. }
            | Self::TlsHello { .. }
            | Self::TunnelData { .. }
            | Self::RuleHit { .. } => 0,
        }
    }

    /// Returns the `pid` field from any variant.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        match self {
            Self::Connect { pid, .. }
            | Self::Disconnect { pid, .. }
            | Self::Send { pid, .. }
            | Self::Recv { pid, .. }
            | Self::RawCapture { pid, .. }
            | Self::DnsQuery { pid, .. }
            | Self::DnsResponse { pid, .. }
            | Self::HttpRequest { pid, .. }
            | Self::DecryptedHttpRequest { pid, .. }
            | Self::HttpResponse { pid, .. }
            | Self::DecryptedHttpResponse { pid, .. }
            | Self::TlsHello { pid, .. }
            | Self::TunnelData { pid, .. } => *pid,
            Self::RuleHit { data } => data.pid,
        }
    }

    /// Returns the `bytes_in` field from any variant.
    #[must_use]
    pub const fn bytes_in(&self) -> u64 {
        match self {
            Self::Connect { bytes_in, .. }
            | Self::Disconnect { bytes_in, .. }
            | Self::Send { bytes_in, .. }
            | Self::Recv { bytes_in, .. } => *bytes_in,
            Self::RawCapture { .. }
            | Self::DnsQuery { .. }
            | Self::DnsResponse { .. }
            | Self::HttpRequest { .. }
            | Self::DecryptedHttpRequest { .. }
            | Self::HttpResponse { .. }
            | Self::DecryptedHttpResponse { .. }
            | Self::TlsHello { .. }
            | Self::TunnelData { .. }
            | Self::RuleHit { .. } => 0,
        }
    }
}
