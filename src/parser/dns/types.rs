//! # `parser::dns::types`
//!
//! **Purpose**: DNS parser public data types and record type mapping.
//! **Public API**: `DnsInfo`, `DnsQueryType`
//! **Dependencies**: `serde`
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 75 / 110

use std::net::IpAddr;

use serde::Serialize;

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Caa,
    Other(u16),
}

impl std::fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(n) => write!(f, "TYPE{n}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl DnsQueryType {
    /// Returns the numeric DNS record type code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Caa => 257,
            Self::Other(code) => code,
        }
    }
}

/// Parsed DNS information from a single UDP payload.
#[derive(Debug, Clone, Serialize)]
pub struct DnsInfo {
    /// Query domain name (e.g. "example.com").
    pub query_name: Option<String>,
    /// Query record type.
    pub query_type: Option<DnsQueryType>,
    /// Response IPs extracted from A/AAAA answer records.
    pub response_ips: Vec<IpAddr>,
    /// DNS response code from the packet header. `None` for queries.
    pub response_code: Option<u32>,
    /// `true` if the DNS TC bit is set and the response may be incomplete.
    pub truncated: bool,
    /// `true` if this is a response packet (QR bit set).
    pub is_response: bool,
}

pub(super) const fn dns_query_type_from_code(qtype: u16) -> DnsQueryType {
    match qtype {
        1 => DnsQueryType::A,
        2 => DnsQueryType::Ns,
        5 => DnsQueryType::Cname,
        6 => DnsQueryType::Soa,
        12 => DnsQueryType::Ptr,
        15 => DnsQueryType::Mx,
        16 => DnsQueryType::Txt,
        28 => DnsQueryType::Aaaa,
        33 => DnsQueryType::Srv,
        257 => DnsQueryType::Caa,
        other => DnsQueryType::Other(other),
    }
}
