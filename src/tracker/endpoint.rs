//! # `tracker::endpoint`
//!
//! **Purpose**: Parses event endpoint strings into connection tuples and remote scope labels.
//! **Public API**: module-private tuple/scope helpers
//! **Dependencies**: `classify`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 85 / 130

use crate::{
    classify,
    parser::types::{FiveTuple, Protocol},
};

/// Parse a `FiveTuple` from the `src` and `dst` address strings in a `NetEvent`.
pub(super) fn parse_tuple_from_addrs(src: &str, dst: &str, proto: Protocol) -> Option<FiveTuple> {
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

/// Classify the remote endpoint IP scope.
pub(super) fn classify_remote(tuple: &FiveTuple) -> Option<&'static str> {
    let dst_ip: std::net::IpAddr = tuple.dst_ip.parse().ok()?;
    let src_ip: std::net::IpAddr = tuple.src_ip.parse().ok()?;
    let remote = if is_local_ip(&dst_ip) {
        &src_ip
    } else {
        &dst_ip
    };

    Some(classify::classify(*remote).label())
}

/// Split `ip:port` into (`ip_string`, `port_u16`).
fn parse_addr_port(addr: &str) -> Option<(String, u16)> {
    if addr.starts_with('[') {
        return parse_bracketed_ipv6_addr_port(addr);
    }
    parse_ipv4_addr_port(addr)
}

fn parse_bracketed_ipv6_addr_port(addr: &str) -> Option<(String, u16)> {
    let close = addr.find(']')?;
    if addr.get(close + 1..close + 2)? != ":" {
        return None;
    }
    let ip: std::net::IpAddr = addr[1..close].parse().ok()?;
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
    let ip: std::net::IpAddr = addr[..colon].parse().ok()?;
    let port = addr[colon + 1..].parse().ok()?;
    Some((ip.to_string(), port))
}

fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    matches!(
        classify::classify(*ip),
        classify::Scope::Loopback | classify::Scope::Private
    )
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
}
