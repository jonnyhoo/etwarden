//! # `mitm::pid`
//!
//! **Purpose**: Maps proxy client sockets back to target PIDs using ETW tuple correlation.
//! **Public API**: `resolve_proxy_pid`
//! **Dependencies**: `parser::types`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 75 / 120

use std::net::SocketAddr;

use crate::{
    parser::types::{FiveTuple, Protocol},
    pcap::correlator::Correlator,
};

/// Resolves the process that owns a client→local-proxy TCP connection.
pub fn resolve_proxy_pid(
    correlator: &Correlator,
    client_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Option<u32> {
    correlator.resolve_pid(&proxy_tuple(client_addr, proxy_addr))
}

fn proxy_tuple(client_addr: SocketAddr, proxy_addr: SocketAddr) -> FiveTuple {
    FiveTuple {
        src_ip: client_addr.ip().to_string(),
        src_port: client_addr.port(),
        dst_ip: proxy_addr.ip().to_string(),
        dst_port: proxy_addr.port(),
        protocol: Protocol::Tcp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_pid_from_client_to_proxy_tuple() {
        let corr = Correlator::new();
        let client = "127.0.0.1:51000".parse().expect("client addr");
        let proxy = "127.0.0.1:3003".parse().expect("proxy addr");
        corr.register_connection(4242, proxy_tuple(client, proxy));

        assert_eq!(resolve_proxy_pid(&corr, client, proxy), Some(4242));
    }

    #[test]
    fn unknown_client_returns_none() {
        let corr = Correlator::new();
        let client = "127.0.0.1:51000".parse().expect("client addr");
        let proxy = "127.0.0.1:3003".parse().expect("proxy addr");

        assert_eq!(resolve_proxy_pid(&corr, client, proxy), None);
    }
}
