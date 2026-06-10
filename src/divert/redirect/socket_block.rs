//! # `divert::redirect::socket_block`
//!
//! **Purpose**: Active socket block evaluation for WinDivert redirect.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: `rules::{block::socket, ruleset}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 61 / 80

#[cfg(test)]
mod tests;

use std::net::Ipv4Addr;

use crate::rules::{
    block::socket::{SocketBlockAction, SocketBlockContext, SocketBlockRule, SocketProtocol},
    ruleset::RuleSet,
};

pub(super) fn tcp_syn_block_action(
    rule_set: Option<&RuleSet>,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<SocketBlockAction> {
    let rule_set = rule_set?;
    socket_block_action(SocketProtocol::Tcp, &rule_set.tcp_block, dst_ip, dst_port)
}

pub(super) fn udp_datagram_block_action(
    rule_set: Option<&RuleSet>,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<SocketBlockAction> {
    let rule_set = rule_set?;
    socket_block_action(SocketProtocol::Udp, &rule_set.udp_block, dst_ip, dst_port)
}

fn socket_block_action(
    protocol: SocketProtocol,
    rules: &[SocketBlockRule],
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<SocketBlockAction> {
    let address = format!("{dst_ip}:{dst_port}");
    let context = SocketBlockContext {
        protocol,
        address: &address,
    };
    rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.matches(&context))
        .filter(|(_, rule)| {
            matches!(
                rule.action,
                SocketBlockAction::Disconnect | SocketBlockAction::DropUpstream
            )
        })
        .min_by_key(|(rule_index, rule)| (rule.priority, *rule_index))
        .map(|(_, rule)| rule.action)
}
