//! # `capture::provider::tcpip::endpoint`
//!
//! **Purpose**: Formats Kernel-Network endpoint fields and decodes network-order ports.
//! **Public API**: module-private endpoint helpers
//! **Dependencies**: `ferrisetw`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 100

use std::net::{IpAddr, Ipv4Addr};

use ferrisetw::parser::Parser;

pub(super) fn format_addr_port(raw_ip: u32, port: u16) -> String {
    let ip = Ipv4Addr::from(raw_ip.to_be());
    format!("{ip}:{port}")
}

pub(super) fn format_ip_addr_port(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(addr) => format!("{addr}:{port}"),
        IpAddr::V6(addr) => format!("[{addr}]:{port}"),
    }
}

pub(super) fn parse_network_port(parser: &Parser<'_, '_>, name: &str) -> Option<u16> {
    parser.try_parse::<u16>(name).ok().map(network_port)
}

const fn network_port(raw: u16) -> u16 {
    u16::from_be(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ip_addr_port_keeps_ipv4_plain() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(format_ip_addr_port(&ip, 443), "127.0.0.1:443");
    }

    #[test]
    fn format_ip_addr_port_brackets_ipv6() {
        let ip = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(format_ip_addr_port(&ip, 443), "[::1]:443");
    }

    #[test]
    fn network_port_decodes_wire_order() {
        let raw = u16::from_ne_bytes(443u16.to_be_bytes());
        assert_eq!(network_port(raw), 443);
    }
}
