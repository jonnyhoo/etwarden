//! # `tracker::ingest`
//!
//! **Purpose**: Extracts trackable connection facts from raw `NetEvent` variants.
//! **Public API**: module-private ingest event projection
//! **Dependencies**: `tracker::endpoint`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 60 / 100

use crate::parser::{
    endpoint::parse_tuple_from_addrs,
    types::{FiveTuple, NetEvent, Protocol},
};

pub(super) struct TrackableEvent {
    pub(super) tuple: FiveTuple,
    pub(super) pid: u32,
    pub(super) proto: Protocol,
    pub(super) bytes_out: u64,
    pub(super) bytes_in: u64,
    pub(super) is_disconnect: bool,
}

impl TrackableEvent {
    pub(super) fn from_net_event(event: &NetEvent) -> Option<Self> {
        let (pid, proto, src, dst, bytes_out, bytes_in, is_disconnect) = match event {
            NetEvent::Connect {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            }
            | NetEvent::Send {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            }
            | NetEvent::Recv {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            } => (*pid, *proto, src, dst, *bytes_out, *bytes_in, false),
            NetEvent::Disconnect {
                pid,
                proto,
                src,
                dst,
                bytes_out,
                bytes_in,
                ..
            } => (*pid, *proto, src, dst, *bytes_out, *bytes_in, true),
            NetEvent::RawCapture { .. }
            | NetEvent::DnsQuery { .. }
            | NetEvent::DnsResponse { .. }
            | NetEvent::HttpRequest { .. }
            | NetEvent::HttpResponse { .. }
            | NetEvent::TlsHello { .. } => return None,
        };

        Some(Self {
            tuple: parse_tuple_from_addrs(src, dst, proto)?,
            pid,
            proto,
            bytes_out,
            bytes_in,
            is_disconnect,
        })
    }
}
