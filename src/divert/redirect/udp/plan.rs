//! # `divert::redirect::udp::plan`
//!
//! **Purpose**: Pure UDP block planning before FlowTable waits.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: `divert::{packet, redirect::{flow, socket_block}}`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 38 / 80

use super::super::{flow::FlowKey, socket_block::udp_datagram_block_action};
use crate::{
    divert::packet::ParsedUdpPacket,
    parser::types::Protocol,
    rules::{block::socket::SocketBlockAction, ruleset::RuleSet},
};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct UdpDatagramPlan {
    pub(super) flow_key: FlowKey,
    pub(super) action: SocketBlockAction,
}

pub(super) fn udp_datagram_plan(
    parsed: &ParsedUdpPacket,
    rule_set: Option<&RuleSet>,
) -> Option<UdpDatagramPlan> {
    let action = udp_datagram_block_action(rule_set, parsed.dst_ip, parsed.dst_port)?;
    Some(UdpDatagramPlan {
        flow_key: FlowKey {
            protocol: Protocol::Udp,
            local_ip: parsed.src_ip.octets(),
            local_port: parsed.src_port,
            remote_ip: parsed.dst_ip.octets(),
            remote_port: parsed.dst_port,
        },
        action,
    })
}
