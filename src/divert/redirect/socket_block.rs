//! # `divert::redirect::socket_block`
//!
//! **Purpose**: Active TCP socket block evaluation for WinDivert redirect.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: `rules::{block::socket, ruleset}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 45 / 80

#[cfg(test)]
mod tests;

use std::net::Ipv4Addr;

use crate::rules::{
    block::socket::{
        evaluate_socket_first, SocketBlockAction, SocketBlockContext, SocketBlockDecision,
        SocketProtocol,
    },
    ruleset::RuleSet,
};

pub(super) fn tcp_syn_block_action(
    rule_set: Option<&RuleSet>,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<SocketBlockAction> {
    let rule_set = rule_set?;
    let address = format!("{dst_ip}:{dst_port}");
    let context = SocketBlockContext {
        protocol: SocketProtocol::Tcp,
        address: &address,
    };
    match evaluate_socket_first(&context, &rule_set.tcp_block) {
        SocketBlockDecision::Block {
            action: action @ (SocketBlockAction::Disconnect | SocketBlockAction::DropUpstream),
            ..
        } => Some(action),
        SocketBlockDecision::Block {
            action: SocketBlockAction::DropDownstream,
            ..
        }
        | SocketBlockDecision::Allow => None,
    }
}
