//! # `parser::tcpip::fields`
//!
//! **Purpose**: Reads Kernel-Network TCP/IP ETW payload fields and formats endpoints.
//! **Public API**: module-private helpers
//! **Dependencies**: `std::net`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 50 / 90

use std::net::{Ipv4Addr, Ipv6Addr};

/// Reads a native-endian `u32` from an ETW payload field.
pub(super) fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|bytes| u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a network-order TCP/UDP port from an ETW payload field.
pub(super) fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn fmt_ipv4(raw: u32) -> String {
    Ipv4Addr::from(raw.to_be()).to_string()
}

pub(super) fn fmt_ipv6(buf: &[u8]) -> Option<String> {
    let octets: [u8; 16] = buf.try_into().ok()?;
    Some(Ipv6Addr::from(octets).to_string())
}

pub(super) fn fmt_addr_port(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

pub(super) fn event_pid(data: &[u8]) -> Option<u32> {
    read_u32(data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_ipv6_rejects_wrong_length() {
        assert!(fmt_ipv6(&[0; 15]).is_none());
    }

    #[test]
    fn fmt_addr_port_brackets_ipv6() {
        assert_eq!(fmt_addr_port("::1", 443), "[::1]:443");
    }

    #[test]
    fn read_u16_reads_network_order_port() {
        assert_eq!(read_u16(&443u16.to_be_bytes(), 0), Some(443));
    }
}
