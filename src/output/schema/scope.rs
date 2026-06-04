//! # `output::schema::scope`
//!
//! **Purpose**: Derives remote IP scope labels from output addr:port strings.
//! **Public API**: module-private `scope_from_addr`
//! **Dependencies**: `classify`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 90

use std::net::IpAddr;

use crate::classify;

/// Classifies the remote address scope from an addr:port string.
pub(super) fn scope_from_addr(addr: &str) -> Option<String> {
    let remote_ip = parse_ip_from_addr(addr)?;
    Some(classify::classify(remote_ip).label().to_string())
}

/// Extracts the IP portion from an `addr:port` string.
fn parse_ip_from_addr(addr: &str) -> Option<IpAddr> {
    if addr.starts_with('[') {
        return parse_bracketed_ipv6_addr(addr);
    }
    parse_ipv4_addr(addr)
}

fn parse_bracketed_ipv6_addr(addr: &str) -> Option<IpAddr> {
    let close = addr.find(']')?;
    if addr.get(close + 1..close + 2)? != ":" {
        return None;
    }
    addr.get(close + 2..)?.parse::<u16>().ok()?;
    addr.get(1..close)?.parse().ok()
}

fn parse_ipv4_addr(addr: &str) -> Option<IpAddr> {
    let colon = addr.rfind(':')?;
    if addr[..colon].contains(':') {
        return None;
    }
    addr.get(colon + 1..)?.parse::<u16>().ok()?;
    addr.get(..colon)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_detects_private_address() {
        assert_eq!(scope_from_addr("10.0.0.1:80"), Some("PRIVATE".into()));
    }

    #[test]
    fn scope_detects_loopback() {
        assert_eq!(scope_from_addr("127.0.0.1:8080"), Some("LOOPBACK".into()));
    }

    #[test]
    fn parse_ip_from_addr_handles_ipv6() {
        let ip = parse_ip_from_addr("[::1]:8080");
        assert_eq!(ip, Some(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));

        let ip = parse_ip_from_addr("192.168.1.1:443");
        assert_eq!(
            ip,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn parse_ip_from_addr_rejects_missing_or_invalid_port() {
        assert_eq!(parse_ip_from_addr("192.168.1.1:"), None);
        assert_eq!(parse_ip_from_addr("192.168.1.1:http"), None);
        assert_eq!(parse_ip_from_addr("[::1]"), None);
        assert_eq!(parse_ip_from_addr("[::1]:http"), None);
        assert_eq!(parse_ip_from_addr("::1:443"), None);
    }
}
