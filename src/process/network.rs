//! # `process::network`
//!
//! **Purpose**: Current OS socket inventory for startup flow attribution.
//! **Public API**: `fn current_tcp_connections_for_pid`
//! **Dependencies**: `netstat2`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 150 / 220

use std::net::IpAddr;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
    TcpSocketInfo, TcpState,
};

use crate::{
    error::EtwardenError,
    parser::types::{FiveTuple, Protocol},
};

/// Returns active TCP 5-tuples currently owned by `pid`.
///
/// # Errors
/// Returns [`EtwardenError::ProcessSpawn`] if the OS socket table cannot be read.
pub fn current_tcp_connections_for_pid(pid: u32) -> Result<Vec<FiveTuple>, EtwardenError> {
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP,
    )
    .map_err(|err| {
        EtwardenError::NetworkInventory(format!("failed to read socket table: {err}"))
    })?;

    Ok(tcp_connections_for_pid(pid, sockets.iter()))
}

fn tcp_connections_for_pid<'a>(
    pid: u32,
    sockets: impl IntoIterator<Item = &'a SocketInfo>,
) -> Vec<FiveTuple> {
    sockets
        .into_iter()
        .filter(|socket| socket.associated_pids.contains(&pid))
        .filter_map(|socket| match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => tcp_socket_to_tuple(tcp),
            ProtocolSocketInfo::Udp(_) => None,
        })
        .collect()
}

fn tcp_socket_to_tuple(socket: &TcpSocketInfo) -> Option<FiveTuple> {
    if socket.state != TcpState::Established {
        return None;
    }
    if is_unspecified(socket.local_addr) || is_unspecified(socket.remote_addr) {
        return None;
    }
    if socket.local_port == 0 || socket.remote_port == 0 {
        return None;
    }

    Some(FiveTuple {
        src_ip: socket.local_addr.to_string(),
        src_port: socket.local_port,
        dst_ip: socket.remote_addr.to_string(),
        dst_port: socket.remote_port,
        protocol: Protocol::Tcp,
    })
}

const fn is_unspecified(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr.is_unspecified(),
        IpAddr::V6(addr) => addr.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn tcp_socket(state: TcpState, local_port: u16, remote_port: u16) -> TcpSocketInfo {
        TcpSocketInfo {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 31, 33)),
            local_port,
            remote_addr: IpAddr::V4(Ipv4Addr::new(14, 19, 160, 45)),
            remote_port,
            state,
        }
    }

    fn socket(pids: Vec<u32>, info: ProtocolSocketInfo) -> SocketInfo {
        SocketInfo {
            protocol_socket_info: info,
            associated_pids: pids,
        }
    }

    #[test]
    fn established_tcp_socket_becomes_five_tuple() {
        let tuple = tcp_socket_to_tuple(&tcp_socket(TcpState::Established, 28_934, 16_669))
            .expect("established tuple");

        assert_eq!(tuple.src_ip, "192.168.31.33");
        assert_eq!(tuple.src_port, 28_934);
        assert_eq!(tuple.dst_ip, "14.19.160.45");
        assert_eq!(tuple.dst_port, 16_669);
        assert_eq!(tuple.protocol, Protocol::Tcp);
    }

    #[test]
    fn listening_tcp_socket_is_not_bootstrapped() {
        assert!(tcp_socket_to_tuple(&tcp_socket(TcpState::Listen, 28_934, 0)).is_none());
    }

    #[test]
    fn unspecified_tcp_socket_is_not_bootstrapped() {
        let socket = TcpSocketInfo {
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 28_934,
            remote_addr: IpAddr::V4(Ipv4Addr::new(14, 19, 160, 45)),
            remote_port: 16_669,
            state: TcpState::Established,
        };

        assert!(tcp_socket_to_tuple(&socket).is_none());
    }

    #[test]
    fn connections_for_pid_filters_owner_and_protocol() {
        let sockets = [
            socket(
                vec![4876],
                ProtocolSocketInfo::Tcp(tcp_socket(TcpState::Established, 28_934, 16_669)),
            ),
            socket(
                vec![9999],
                ProtocolSocketInfo::Tcp(tcp_socket(TcpState::Established, 40_000, 443)),
            ),
            socket(
                vec![4876],
                ProtocolSocketInfo::Tcp(tcp_socket(TcpState::Listen, 28_934, 0)),
            ),
        ];

        let tuples = tcp_connections_for_pid(4876, sockets.iter());

        assert_eq!(tuples.len(), 1);
        assert_eq!(tuples[0].src_port, 28_934);
        assert_eq!(tuples[0].dst_port, 16_669);
    }
}
