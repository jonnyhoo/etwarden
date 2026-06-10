//! # `divert::redirect::udp::tests`
//!
//! **Purpose**: Unit tests for UDP redirect planning.
//! **Public API**: test module only
//! **Dependencies**: `divert::redirect::udp`, `rules`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 76 / 80

use std::net::Ipv4Addr;

use super::plan::udp_datagram_plan;
use crate::{
    divert::{packet::ParsedUdpPacket, redirect::flow::FlowKey},
    parser::types::Protocol,
    rules::{
        block::socket::{SocketBlockAction, SocketBlockRule, SocketProtocol},
        matcher::MatchOperator,
        ruleset::RuleSet,
    },
};

fn rule(pattern: &str, action: SocketBlockAction) -> SocketBlockRule {
    SocketBlockRule::new(
        true,
        10,
        SocketProtocol::Udp,
        MatchOperator::Equals,
        pattern,
        action,
    )
    .expect("rule")
}

fn udp(dst_ip: Ipv4Addr, dst_port: u16) -> ParsedUdpPacket {
    ParsedUdpPacket {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip,
        src_port: 51_000,
        dst_port,
        ip_header_len: 20,
        udp_len: 8,
    }
}

#[test]
fn udp_datagram_plan_skips_unmatched_rules() {
    let rules = RuleSet {
        udp_block: vec![rule("93.184.216.34:443", SocketBlockAction::DropUpstream)],
        ..RuleSet::default()
    };

    assert!(udp_datagram_plan(&udp(Ipv4Addr::new(1, 1, 1, 1), 53), Some(&rules)).is_none());
}

#[test]
fn udp_datagram_plan_builds_flow_key_for_enforceable_rule() {
    let rules = RuleSet {
        udp_block: vec![rule("93.184.216.34:443", SocketBlockAction::DropUpstream)],
        ..RuleSet::default()
    };

    let plan =
        udp_datagram_plan(&udp(Ipv4Addr::new(93, 184, 216, 34), 443), Some(&rules)).expect("plan");

    assert_eq!(plan.action, SocketBlockAction::DropUpstream);
    assert_eq!(
        plan.flow_key,
        FlowKey {
            protocol: Protocol::Udp,
            local_port: 51_000,
            remote_ip: [93, 184, 216, 34],
            remote_port: 443,
        },
    );
}
