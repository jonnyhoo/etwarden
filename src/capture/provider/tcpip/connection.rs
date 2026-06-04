//! # `capture::provider::tcpip::connection`
//!
//! **Purpose**: Builds TCP connect/disconnect events from Kernel-Network endpoint fields.
//! **Public API**: module-private connection event constructors
//! **Dependencies**: `ferrisetw`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 80 / 120

use chrono::{DateTime, Utc};
use ferrisetw::parser::Parser;

use super::endpoint::{parse_endpoints_v4, parse_endpoints_v6, Endpoints};
use crate::parser::types::{NetEvent, Protocol};

pub(super) fn parse_connect_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: DateTime<Utc>,
) -> Option<NetEvent> {
    Some(connect_event(pid, ts, parse_endpoints_v4(parser)?))
}

pub(super) fn parse_connect_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: DateTime<Utc>,
) -> Option<NetEvent> {
    Some(connect_event(pid, ts, parse_endpoints_v6(parser)?))
}

pub(super) fn parse_disconnect_v4(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: DateTime<Utc>,
) -> Option<NetEvent> {
    Some(disconnect_event(pid, ts, parse_endpoints_v4(parser)?))
}

pub(super) fn parse_disconnect_v6(
    parser: &Parser<'_, '_>,
    pid: u32,
    ts: DateTime<Utc>,
) -> Option<NetEvent> {
    Some(disconnect_event(pid, ts, parse_endpoints_v6(parser)?))
}

fn connect_event(pid: u32, ts: DateTime<Utc>, endpoints: Endpoints) -> NetEvent {
    NetEvent::Connect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: endpoints.src,
        dst: endpoints.dst,
        bytes_out: 0,
        bytes_in: 0,
    }
}

fn disconnect_event(pid: u32, ts: DateTime<Utc>, endpoints: Endpoints) -> NetEvent {
    NetEvent::Disconnect {
        timestamp: ts,
        pid,
        proto: Protocol::Tcp,
        src: endpoints.src,
        dst: endpoints.dst,
        bytes_out: 0,
        bytes_in: 0,
    }
}
