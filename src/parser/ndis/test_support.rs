//! # `parser::ndis::test_support`
//!
//! **Purpose**: Shared NDIS parser test fixtures.
//! **Public API**: test-only frame and DNS packet builders
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 145 / 200

use chrono::{DateTime, TimeZone, Utc};

use crate::parser::types::RawEvent;

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xDD];
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

pub(super) fn ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

pub(super) fn raw_ndis(data: Vec<u8>) -> RawEvent {
    RawEvent {
        event_id: 1,
        pid: 99,
        timestamp: ts(),
        data,
    }
}

pub(super) fn build_ethernet_ipv4_tcp(payload_len: usize) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF; 6]);
    frame.extend_from_slice(&[0xAA; 6]);
    frame.extend_from_slice(&ETHERTYPE_IPV4);
    frame.push(0x45);
    frame.push(0x00);
    let total_len = u16::try_from(20 + 20 + payload_len).expect("fits in u16");
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x40, 0x00]);
    frame.push(0x40);
    frame.push(IPPROTO_TCP);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[10, 0, 0, 1]);
    frame.extend_from_slice(&[10, 0, 0, 2]);
    frame.extend_from_slice(&1234u16.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&[0u8; 8]);
    frame.push(0x50);
    frame.extend_from_slice(&[0u8; 7]);
    frame.extend_from_slice(&vec![0xDD; payload_len]);
    frame
}

pub(super) fn build_ieee80211_snap_from_ethernet(ethernet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x08, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x78, 0x60, 0x5b, 0x18, 0xb1, 0x14]);
    frame.extend_from_slice(&ethernet[6..12]);
    frame.extend_from_slice(&ethernet[0..6]);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&ethernet[12..14]);
    frame.extend_from_slice(&ethernet[14..]);
    frame
}

pub(super) fn build_ethernet_ipv4_udp(payload: &[u8], src_port: u16, dst_port: u16) -> Vec<u8> {
    build_ethernet_ipv4_udp_with_ips(payload, [10, 0, 0, 1], [8, 8, 8, 8], src_port, dst_port)
}

pub(super) fn build_ethernet_ipv4_udp_with_ips(
    payload: &[u8],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF; 6]);
    frame.extend_from_slice(&[0xAA; 6]);
    frame.extend_from_slice(&ETHERTYPE_IPV4);
    frame.push(0x45);
    frame.push(0x00);
    let total_len = u16::try_from(20 + 8 + payload.len()).expect("fits in u16");
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x40, 0x00]);
    frame.push(0x40);
    frame.push(IPPROTO_UDP);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = u16::try_from(8 + payload.len()).expect("fits in u16");
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(payload);
    frame
}

pub(super) fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        let bytes = label.as_bytes();
        pkt.push(u8::try_from(bytes.len()).expect("label fits"));
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt
}

pub(super) fn build_dns_response_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
    let mut pkt = build_dns_query(name, 1);
    pkt[2] |= 0x80;
    pkt[6] = 0x00;
    pkt[7] = 0x01;
    pkt.extend_from_slice(&[0xC0, 0x0C]);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
    pkt.extend_from_slice(&ip);
    pkt
}

pub(super) fn build_ethernet_ipv6_udp(payload_len: usize) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF; 6]);
    frame.extend_from_slice(&[0xAA; 6]);
    frame.extend_from_slice(&ETHERTYPE_IPV6);
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    let payload_len_u16 = u16::try_from(8 + payload_len).expect("fits in u16");
    frame.extend_from_slice(&payload_len_u16.to_be_bytes());
    frame.push(IPPROTO_UDP);
    frame.push(0x40);
    frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&5678u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    let udp_len = u16::try_from(8 + payload_len).expect("fits in u16");
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&vec![0xEE; payload_len]);
    frame
}
