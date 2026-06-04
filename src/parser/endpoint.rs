//! # `parser::endpoint`
//!
//! **Purpose**: Parses endpoint strings into canonical IP/port pairs and five-tuples.
//! **Public API**: crate-private endpoint parsing helpers
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 75 / 120

use std::net::IpAddr;

use crate::parser::types::{FiveTuple, Protocol};

/// Parse a `FiveTuple` from `src` and `dst` address strings in a `NetEvent`.
pub fn parse_tuple_from_addrs(src: &str, dst: &str, proto: Protocol) -> Option<FiveTuple> {
    let (src_ip, src_port) = parse_addr_port(src)?;
    let (dst_ip, dst_port) = parse_addr_port(dst)?;
    Some(FiveTuple {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: proto,
    })
}

/// Format an IP and port using the same endpoint syntax emitted by TCPIP ETW parsers.
#[must_use]
pub fn format_addr_port(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Split `ip:port` into (`ip_string`, `port_u16`).
fn parse_addr_port(addr: &str) -> Option<(String, u16)> {
    if addr.starts_with('[') {
        return parse_bracketed_addr_port(addr);
    }
    parse_ipv4_addr_port(addr)
}

fn parse_bracketed_addr_port(addr: &str) -> Option<(String, u16)> {
    let close = addr.find(']')?;
    if addr.get(close + 1..close + 2)? != ":" {
        return None;
    }
    let ip: IpAddr = addr[1..close].parse().ok()?;
    let port = addr.get(close + 2..)?.parse().ok()?;
    Some((ip.to_string(), port))
}

fn parse_ipv4_addr_port(addr: &str) -> Option<(String, u16)> {
    if addr.contains('[') || addr.contains(']') {
        return None;
    }

    let colon = addr.rfind(':')?;
    if addr[..colon].contains(':') {
        return None;
    }
    let ip: IpAddr = addr[..colon].parse().ok()?;
    let port = addr[colon + 1..].parse().ok()?;
    Some((ip.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_port_ipv4() {
        let (ip, port) = parse_addr_port("192.168.1.1:443").expect("valid ipv4 addr");
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, 443);
        assert!(parse_addr_port("not-ip:443").is_none());
    }

    #[test]
    fn parse_addr_port_ipv6() {
        let (ip, port) = parse_addr_port("[::1]:443").expect("valid ipv6 addr");
        assert_eq!(ip, "::1");
        assert_eq!(port, 443);
        assert!(parse_addr_port("[::1]").is_none());
        assert!(parse_addr_port("x]::1:443").is_none());
        assert!(parse_addr_port("::1:443").is_none());
        assert!(parse_addr_port("[not-ip]:443").is_none());
    }

    #[test]
    fn format_addr_port_brackets_ipv6_only() {
        assert_eq!(format_addr_port("192.168.1.1", 443), "192.168.1.1:443");
        assert_eq!(format_addr_port("::1", 443), "[::1]:443");
    }
}
