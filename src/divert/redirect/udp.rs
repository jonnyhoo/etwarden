//! # `divert::redirect::udp`
//!
//! **Purpose**: UDP block handling for WinDivert NETWORK packets.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: `divert::{ffi, packet, redirect::flow}`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 74 / 80

mod plan;
#[cfg(test)]
mod tests;

use plan::udp_datagram_plan;

use super::{
    flow::{wait_for_flow_match, FlowTable},
    DivertConfig,
};
use crate::{
    divert::{
        ffi::{WinDivertAddress, WinDivertHandle},
        packet::parse_ipv4_udp,
    },
    output::diagnostic,
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

    let Some(plan) = udp_datagram_plan(&parsed, config.rule_set.as_deref()) else {
        let pkt = packet.to_vec();
        let _ = handle.send(&pkt, addr);
        return true;
    };

    let mut matched_pid = {
        let table = flow_table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table.get(&plan.flow_key).copied()
    };
    if matched_pid.is_none() {
        matched_pid = wait_for_flow_match(flow_table, &plan.flow_key);
    }
    let Some(pid) = matched_pid else {
        let pkt = packet.to_vec();
        let _ = handle.send(&pkt, addr);
        return true;
    };

    diagnostic::warn(format_args!(
        "SOCKET block {:?} PID={pid} UDP {}:{} -> {}:{}",
        plan.action, parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port,
    ));
    true
}
