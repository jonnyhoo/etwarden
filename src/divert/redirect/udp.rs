//! # `divert::redirect::udp`
//!
//! **Purpose**: UDP block handling for WinDivert NETWORK packets.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: `divert::{ffi, packet, redirect::flow}`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 78 / 80

use super::{
    flow::{wait_for_flow_match, FlowKey, FlowTable},
    socket_block::udp_datagram_block_action,
    DivertConfig,
};
use crate::{
    divert::{
        ffi::{WinDivertAddress, WinDivertHandle},
        packet::parse_ipv4_udp,
    },
    output::diagnostic,
    parser::types::Protocol,
};

pub(super) fn handle_udp_datagram(
    packet: &[u8],
    handle: &WinDivertHandle,
    addr: &WinDivertAddress,
    flow_table: &FlowTable,
    config: &DivertConfig,
) -> bool {
    let Some(parsed) = parse_ipv4_udp(packet) else {
        return false;
    };
    if config
        .rule_set
        .as_ref()
        .is_none_or(|rules| rules.udp_block.is_empty())
    {
        let pkt = packet.to_vec();
        let _ = handle.send(&pkt, addr);
        return true;
    }

    let lookup = FlowKey {
        protocol: Protocol::Udp,
        local_port: parsed.src_port,
        remote_ip: parsed.dst_ip.octets(),
        remote_port: parsed.dst_port,
    };
    let mut matched_pid = {
        let table = flow_table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table.get(&lookup).copied()
    };
    if matched_pid.is_none() {
        matched_pid = wait_for_flow_match(flow_table, &lookup);
    }
    let Some(pid) = matched_pid else {
        let pkt = packet.to_vec();
        let _ = handle.send(&pkt, addr);
        return true;
    };

    if let Some(action) =
        udp_datagram_block_action(config.rule_set.as_deref(), parsed.dst_ip, parsed.dst_port)
    {
        diagnostic::warn(format_args!(
            "SOCKET block {:?} PID={pid} UDP {}:{} -> {}:{}",
            action, parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port,
        ));
        return true;
    }

    let pkt = packet.to_vec();
    let _ = handle.send(&pkt, addr);
    true
}
