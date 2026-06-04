//! # `pcap::correlator::tuple`
//!
//! **Purpose**: Parses tuple-bearing events and endpoint strings for pcap PID correlation.
//! **Public API**: module-private tuple helpers
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 55 / 100

use crate::parser::{
    endpoint::parse_tuple_from_addrs,
    types::{FiveTuple, NetEvent, Protocol},
};

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
        NetEvent::HttpRequest { pid, src, dst, .. }
        | NetEvent::DecryptedHttpRequest { pid, src, dst, .. }
        | NetEvent::HttpResponse { pid, src, dst, .. }
        | NetEvent::DecryptedHttpResponse { pid, src, dst, .. }
        | NetEvent::TlsHello { pid, src, dst, .. } => Some((*pid, Protocol::Tcp, src, dst)),
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
    parse_tuple_from_addrs(src, dst, proto)
}
