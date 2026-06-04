//! # `pcap::correlator::tuple`
//!
//! **Purpose**: Parses tuple-bearing events and endpoint strings for pcap PID correlation.
//! **Public API**: module-private tuple helpers
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 95 / 130

use std::net::IpAddr;

use crate::parser::types::{FiveTuple, NetEvent, Protocol};

pub(super) fn event_tuple_parts(event: &NetEvent) -> Option<(u32, Protocol, &str, &str)> {
    match event {
        NetEvent::Connect {
            pid,
            proto,
            src,
            dst,
            ..
        }
        | NetEvent::Send {
            pid,
            proto,
            src,
            dst,
            ..
        }
        | NetEvent::Recv {
            pid,
            proto,
            src,
            dst,
            ..
        } => Some((*pid, *proto, src, dst)),
        NetEvent::Disconnect { .. }
        | NetEvent::RawCapture { .. }
        | NetEvent::DnsQuery { .. }
        | NetEvent::DnsResponse { .. } => None,
    }
}

pub(super) fn reverse_tuple(tuple: &FiveTuple) -> FiveTuple {
    FiveTuple {
        src_ip: tuple.dst_ip.clone(),
        src_port: tuple.dst_port,
        dst_ip: tuple.src_ip.clone(),
        dst_port: tuple.src_port,
        protocol: tuple.protocol,
    }
}

pub(super) fn parse_tuple_from_event(src: &str, dst: &str, proto: Protocol) -> Option<FiveTuple> {
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
    fn parse_addr_port_rejects_malformed_ipv6_brackets() {
        assert!(parse_addr_port("[::1]").is_none());
        assert!(parse_addr_port("x]::1:443").is_none());
        assert!(parse_addr_port("::1:443").is_none());
        assert!(parse_addr_port("not-ip:443").is_none());
        assert!(parse_addr_port("[not-ip]:443").is_none());
    }
}
