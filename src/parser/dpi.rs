//! # `parser::dpi`
//!
//! **Purpose**: Deep Packet Inspection dispatch — detects application-layer protocols
//!   from raw TCP/UDP payloads extracted from NDIS frames.
//! **Public API**: `DpiResult`, `HttpInfo`, `TlsInfo`, `analyze_tcp_payload`,
//!   `analyze_udp_payload`
//! **Dependencies**: `parser::dns`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 95 / 140

mod http;
mod tls;

pub use http::HttpInfo;
use serde::Serialize;
pub use tls::TlsInfo;

use crate::parser::dns::{self, DnsInfo};

const PORT_DNS: u16 = 53;
const PORT_HTTPS: u16 = 443;

/// Result of DPI analysis on a single packet payload.
#[derive(Debug, Clone, Serialize)]
pub enum DpiResult {
    /// DNS query or response detected.
    Dns(DnsInfo),
    /// Plaintext HTTP request or response.
    Http(HttpInfo),
    /// TLS `ClientHello` with extracted SNI.
    Tls(TlsInfo),
}

/// Analyze a TCP payload for application-layer protocol detection.
///
/// Dispatches to protocol-specific parsers ordered by likelihood and speed.
/// Returns `None` if no known protocol is detected.
#[must_use]
pub fn analyze_tcp_payload(payload: &[u8], src_port: u16, dst_port: u16) -> Option<DpiResult> {
    if payload.is_empty() {
        return None;
    }

    if let Some(http_info) = http::analyze_http(payload) {
        return Some(DpiResult::Http(http_info));
    }

    if src_port == PORT_HTTPS || dst_port == PORT_HTTPS || tls::is_tls_handshake(payload) {
        if let Some(tls_info) = tls::analyze_tls_hello(payload) {
            return Some(DpiResult::Tls(tls_info));
        }
    }

    None
}

/// Analyze a UDP payload for application-layer protocol detection.
#[must_use]
pub fn analyze_udp_payload(payload: &[u8], src_port: u16, dst_port: u16) -> Option<DpiResult> {
    if payload.is_empty() {
        return None;
    }

    if src_port == PORT_DNS || dst_port == PORT_DNS {
        if let Some(dns_info) = dns::analyze_dns(payload) {
            return Some(DpiResult::Dns(dns_info));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_udp_dispatch() {
        let pkt = build_test_query("example.com", 1);
        let result = analyze_udp_payload(&pkt, 50234, 53);
        assert!(result.is_some(), "should detect DNS on port 53");
    }

    #[test]
    fn empty_payload_returns_none() {
        assert!(analyze_tcp_payload(&[], 80, 8080).is_none());
        assert!(analyze_udp_payload(&[], 53, 53).is_none());
    }

    fn build_test_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            let bytes = label.as_bytes();
            pkt.push(u8::try_from(bytes.len()).unwrap_or(255));
            pkt.extend_from_slice(bytes);
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt
    }
}
