//! # `parser::tcpip::layout`
//!
//! **Purpose**: Parses fixed Kernel-Network TCP/IP payload layouts.
//! **Public API**: module-private layout readers
//! **Dependencies**: `parser::tcpip::fields`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 95 / 140

use crate::parser::tcpip::fields::{
    event_pid, fmt_addr_port, fmt_ipv4, fmt_ipv6, read_u16, read_u32,
};

const IPV4_LAYOUT_LEN: usize = 20;
const IPV6_LAYOUT_LEN: usize = 44;

pub(super) struct TcpIpFields {
    pub(super) pid: u32,
    pub(super) size: u32,
    pub(super) src: String,
    pub(super) dst: String,
}

pub(super) fn parse_v4_fields(data: &[u8]) -> Option<TcpIpFields> {
    if data.len() < IPV4_LAYOUT_LEN {
        return None;
    }

    let pid = event_pid(data)?;
    let size = read_u32(data, 4)?;
    let daddr = read_u32(data, 8)?;
    let saddr = read_u32(data, 12)?;
    let dport = read_u16(data, 16)?;
    let sport = read_u16(data, 18)?;

    Some(TcpIpFields {
        pid,
        size,
        src: fmt_addr_port(&fmt_ipv4(saddr), sport),
        dst: fmt_addr_port(&fmt_ipv4(daddr), dport),
    })
}

pub(super) fn parse_v6_fields(data: &[u8]) -> Option<TcpIpFields> {
    if data.len() < IPV6_LAYOUT_LEN {
        return None;
    }

    let pid = event_pid(data)?;
    let size = read_u32(data, 4)?;
    let daddr = data.get(8..24)?;
    let saddr = data.get(24..40)?;
    let dport = read_u16(data, 40)?;
    let sport = read_u16(data, 42)?;
    let dst_ip = fmt_ipv6(daddr)?;
    let src_ip = fmt_ipv6(saddr)?;

    Some(TcpIpFields {
        pid,
        size,
        src: fmt_addr_port(&src_ip, sport),
        dst: fmt_addr_port(&dst_ip, dport),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_v4() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_ne_bytes());
        data.extend_from_slice(&128u32.to_ne_bytes());
        data.extend_from_slice(&0x0100_007fu32.to_ne_bytes());
        data.extend_from_slice(&0x0101_a8c0u32.to_ne_bytes());
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(&4802u16.to_be_bytes());
        data
    }

    #[test]
    fn parse_v4_fields_reads_endpoint_layout() {
        let fields = parse_v4_fields(&raw_v4()).expect("fields");
        assert_eq!(fields.pid, 42);
        assert_eq!(fields.size, 128);
        assert_eq!(fields.src, "192.168.1.1:4802");
        assert_eq!(fields.dst, "127.0.0.1:443");
    }

    #[test]
    fn parse_v4_fields_rejects_truncated_layout() {
        assert!(parse_v4_fields(&raw_v4()[..19]).is_none());
    }
}
