//! # `parser::dns::records`
//!
//! **Purpose**: Parses DNS question and answer record sections.
//! **Public API**: module-private section walkers
//! **Dependencies**: `parser::dns::name`, `parser::dns::types`
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 90 / 140

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::parser::dns::{
    name::parse_dns_name,
    types::{dns_query_type_from_code, DnsQueryType},
};

/// Cap on answer records walked per packet.
const MAX_ANSWERS_TO_PARSE: usize = 64;
/// Cap on response IPs surfaced per packet.
const MAX_RESPONSE_IPS_PER_PACKET: usize = 16;

/// Parse a single question section, returning (name, `query_type`, `offset_after`).
pub(super) fn parse_question(
    payload: &[u8],
    start: usize,
) -> Option<(Option<String>, Option<DnsQueryType>, usize)> {
    let (query_name, mut offset) = parse_dns_name(payload, start, false)?;
    if offset >= payload.len() {
        return None;
    }

    if offset.checked_add(4).is_none_or(|end| end > payload.len()) {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    let query_type = Some(dns_query_type_from_code(qtype));
    offset += 4;

    Some((query_name, query_type, offset))
}

/// Walk answer records, extracting A/AAAA response IPs.
pub(super) fn walk_a_aaaa_records(
    payload: &[u8],
    start: usize,
    count: usize,
    ips: &mut Vec<IpAddr>,
    answer_question: &mut Option<(String, DnsQueryType)>,
) -> Option<usize> {
    let mut offset = start;
    let count = count.min(MAX_ANSWERS_TO_PARSE);
    for _ in 0..count {
        let (answer_name, after_name) = parse_dns_name(payload, offset, true)?;
        if after_name
            .checked_add(10)
            .is_none_or(|end| end > payload.len())
        {
            return None;
        }

        let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
        let answer_type = dns_query_type_from_code(atype);
        let rdlength = usize::from(u16::from_be_bytes([
            payload[after_name + 8],
            payload[after_name + 9],
        ]));
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > payload.len() {
            return None;
        }

        if ips.len() < MAX_RESPONSE_IPS_PER_PACKET {
            capture_ip_answer(
                payload,
                rdata_start,
                rdata_end,
                atype,
                answer_type,
                answer_name.as_ref(),
                ips,
                answer_question,
            )?;
        }
        offset = rdata_end;
    }
    Some(offset)
}

#[expect(
    clippy::too_many_arguments,
    reason = "DNS answer projection needs explicit bounds"
)]
fn capture_ip_answer(
    payload: &[u8],
    rdata_start: usize,
    rdata_end: usize,
    atype: u16,
    answer_type: DnsQueryType,
    answer_name: Option<&String>,
    ips: &mut Vec<IpAddr>,
    answer_question: &mut Option<(String, DnsQueryType)>,
) -> Option<()> {
    match atype {
        1 if rdata_end - rdata_start == 4 => {
            set_answer_question(answer_question, answer_name, answer_type);
            let octets: [u8; 4] = payload[rdata_start..rdata_end].try_into().ok()?;
            ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
        }
        28 if rdata_end - rdata_start == 16 => {
            set_answer_question(answer_question, answer_name, answer_type);
            let octets: [u8; 16] = payload[rdata_start..rdata_end].try_into().ok()?;
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        _ => {}
    }
    Some(())
}

fn set_answer_question(
    answer_question: &mut Option<(String, DnsQueryType)>,
    answer_name: Option<&String>,
    answer_type: DnsQueryType,
) {
    if answer_question.is_none() {
        if let Some(name) = answer_name {
            *answer_question = Some((name.clone(), answer_type));
        }
    }
}
