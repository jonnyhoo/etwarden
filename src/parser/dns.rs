//! # `parser::dns`
//!
//! **Purpose**: DNS deep-packet-inspection parser — extract query names, types, and response IPs
//!   from raw DNS UDP payloads (RFC 1035).
//! **Public API**: `struct DnsInfo`, `fn analyze_dns(&[u8]) -> Option<DnsInfo>`
//! **Dependencies**: (none)
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 381 / 420

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum DNS name length per RFC 1035 §2.3.4.
const MAX_DNS_NAME_LEN: usize = 253;
/// Cap on answer records walked per packet.
const MAX_ANSWERS_TO_PARSE: usize = 64;
/// Cap on response IPs surfaced per packet.
const MAX_RESPONSE_IPS_PER_PACKET: usize = 16;
/// Cap on pointer indirection hops while skipping a name.
const MAX_NAME_POINTER_HOPS: usize = 16;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
    /// `true` if this is a response packet (QR bit set).
    pub is_response: bool,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Walk a DNS name in the answer section, returning the offset after the name.
/// Handles compression pointers (0xC0 prefix) with hop limit.
fn skip_dns_name(payload: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    let mut hops = 0;
    loop {
        let label_len = *payload.get(offset)? as usize;
        if label_len == 0 {
            return Some(offset + 1);
        }
        if label_len & 0xC0 == 0xC0 {
            if offset + 1 >= payload.len() {
                return None;
            }
            hops += 1;
            if hops > MAX_NAME_POINTER_HOPS {
                return None;
            }
            return Some(offset + 2);
        }
        if label_len & 0xC0 != 0 {
            return None;
        }
        let next = offset.checked_add(1)?.checked_add(label_len)?;
        if next > payload.len() {
            return None;
        }
        offset = next;
    }
}

/// Parse a single question section, returning (name, `query_type`, `offset_after`).
fn parse_question(
    payload: &[u8],
    start: usize,
) -> Option<(Option<String>, Option<DnsQueryType>, usize)> {
    let mut offset = start;
    let mut name = String::new();

    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }
        if label_len & 0xC0 != 0 {
            return None;
        }
        if offset + 1 + label_len > payload.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = std::str::from_utf8(&payload[offset + 1..offset + 1 + label_len]).ok()?;
        name.push_str(label);
        if name.len() > MAX_DNS_NAME_LEN {
            return None;
        }
        offset += 1 + label_len;
    }
    if offset >= payload.len() {
        return None;
    }

    let query_name = if name.is_empty() { None } else { Some(name) };

    if offset.checked_add(4).is_none_or(|e| e > payload.len()) {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    let query_type = Some(match qtype {
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
    });
    offset += 4;

    Some((query_name, query_type, offset))
}

/// Walk answer records, extracting A/AAAA response IPs.
fn walk_a_aaaa_records(
    payload: &[u8],
    start: usize,
    count: usize,
    ips: &mut Vec<IpAddr>,
) -> Option<usize> {
    let mut offset = start;
    let count = count.min(MAX_ANSWERS_TO_PARSE);
    for _ in 0..count {
        let after_name = skip_dns_name(payload, offset)?;
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10
        if after_name.checked_add(10).is_none_or(|e| e > payload.len()) {
            return None;
        }
        let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
        let rdlength =
            u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = match rdata_start.checked_add(rdlength) {
            Some(e) if e <= payload.len() => e,
            _ => return None,
        };

        if ips.len() < MAX_RESPONSE_IPS_PER_PACKET {
            match atype {
                1 if rdlength == 4 => {
                    let octets: [u8; 4] = payload[rdata_start..rdata_end].try_into().ok()?;
                    ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
                28 if rdlength == 16 => {
                    let octets: [u8; 16] = payload[rdata_start..rdata_end].try_into().ok()?;
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset = rdata_end;
    }
    Some(offset)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Analyze a raw DNS payload (UDP, port 53).
///
/// Returns `None` if the payload is too short or the DNS header is malformed.
#[must_use]
pub fn analyze_dns(payload: &[u8]) -> Option<DnsInfo> {
    // DNS header is 12 bytes minimum.
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags >> 15) & 1 == 1;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    // Parse first question only (most common case).
    let (query_name, query_type, offset) = if qdcount > 0 {
        parse_question(payload, 12)?
    } else {
        (None, None, 12)
    };

    let mut response_ips = Vec::new();
    if ancount > 0 && is_response {
        walk_a_aaaa_records(payload, offset, ancount, &mut response_ips)?;
    }

    Some(DnsInfo {
        query_name,
        query_type,
        response_ips,
        response_code: is_response.then_some(u32::from(flags & 0x000F)),
        is_response,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet.
    fn build_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        // Encode name as DNS labels
        for label in name.split('.') {
            let bytes = label.as_bytes();
            pkt.push(u8::try_from(bytes.len()).unwrap_or(255));
            pkt.extend_from_slice(bytes);
        }
        pkt.push(0); // root label
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        pkt
    }

    /// Build a DNS response with A records.
    fn build_response_a(name: &str, qtype: u16, ips: &[&[u8; 4]]) -> Vec<u8> {
        let mut pkt = build_query(name, qtype);
        // Set QR bit
        pkt[2] |= 0x80;
        // Set ANCOUNT
        pkt[6] = 0x00;
        pkt[7] = u8::try_from(ips.len()).unwrap_or(255);

        for ip in ips {
            // Name pointer to question
            pkt.extend_from_slice(&[0xC0, 0x0C]);
            // TYPE A, CLASS IN, TTL 300, RDLENGTH 4
            pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
            pkt.extend_from_slice(ip.as_slice());
        }
        pkt
    }

    #[test]
    fn empty_payload_returns_none() {
        assert!(analyze_dns(&[]).is_none());
    }

    #[test]
    fn short_payload_returns_none() {
        assert!(analyze_dns(&[0u8; 11]).is_none());
    }

    #[test]
    fn query_parses_name_and_type() {
        let pkt = build_query("example.com", 1);
        let info = analyze_dns(&pkt).expect("parse");
        assert_eq!(info.query_name.as_deref(), Some("example.com"));
        assert_eq!(info.query_type, Some(DnsQueryType::A));
        assert_eq!(info.query_type.expect("qtype").code(), 1);
        assert!(!info.is_response);
        assert_eq!(info.response_code, None);
        assert!(info.response_ips.is_empty());
    }

    #[test]
    fn response_with_a_record() {
        let pkt = build_response_a("example.com", 1, &[&[93, 184, 216, 34]]);
        let info = analyze_dns(&pkt).expect("parse");
        assert!(info.is_response);
        assert_eq!(info.response_code, Some(0));
        assert_eq!(info.response_ips.len(), 1);
        assert_eq!(
            info.response_ips[0],
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn response_with_multiple_a_records() {
        let pkt = build_response_a("example.com", 1, &[&[1, 1, 1, 1], &[1, 0, 0, 1]]);
        let info = analyze_dns(&pkt).expect("parse");
        assert_eq!(info.response_ips.len(), 2);
    }

    #[test]
    fn truncated_answer_returns_none() {
        let mut pkt = build_response_a("example.com", 1, &[&[93, 184, 216, 34]]);
        pkt.truncate(pkt.len() - 2);

        assert!(analyze_dns(&pkt).is_none());
    }

    #[test]
    fn aaaa_query_type() {
        let pkt = build_query("example.com", 28);
        let info = analyze_dns(&pkt).expect("parse");
        assert_eq!(info.query_type, Some(DnsQueryType::Aaaa));
    }

    #[test]
    fn unknown_query_type() {
        let pkt = build_query("example.com", 99);
        let info = analyze_dns(&pkt).expect("parse");
        assert_eq!(info.query_type, Some(DnsQueryType::Other(99)));
    }

    #[test]
    fn query_no_question() {
        let pkt = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let info = analyze_dns(&pkt).expect("parse");
        assert!(info.query_name.is_none());
        assert!(info.query_type.is_none());
    }

    #[test]
    fn truncated_question_returns_none() {
        let mut pkt = build_query("example.com", 1);
        pkt.truncate(pkt.len() - 2);

        assert!(analyze_dns(&pkt).is_none());
    }

    #[test]
    fn compressed_question_name_returns_none() {
        let pkt = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
        ];

        assert!(analyze_dns(&pkt).is_none());
    }

    #[test]
    fn invalid_utf8_question_label_returns_none() {
        let pkt = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x01, 0xFF, // invalid UTF-8 label
            0x00, // root label
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];

        assert!(analyze_dns(&pkt).is_none());
    }
}
