//! # `parser::tcpip::events`
//!
//! **Purpose**: Parses Kernel-Network TCP/IP event IDs into typed `NetEvent` variants.
//! **Public API**: module-private event dispatcher
//! **Dependencies**: `parser::tcpip::fields`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 185 / 240

use chrono::{DateTime, Utc};

use super::{
    ids::{
        EVENT_ID_TCP_CONNECT_IPV4, EVENT_ID_TCP_CONNECT_IPV6, EVENT_ID_TCP_DISCONNECT_IPV4,
        EVENT_ID_TCP_DISCONNECT_IPV6, EVENT_ID_TCP_RECV_IPV4, EVENT_ID_TCP_RECV_IPV6,
        EVENT_ID_TCP_RETRANSMIT_IPV4, EVENT_ID_TCP_RETRANSMIT_IPV6, EVENT_ID_TCP_SEND_IPV4,
        EVENT_ID_TCP_SEND_IPV6, EVENT_ID_UDP_RECV_IPV4, EVENT_ID_UDP_RECV_IPV6,
        EVENT_ID_UDP_SEND_IPV4, EVENT_ID_UDP_SEND_IPV6,
    },
    layout::{parse_v4_fields, parse_v6_fields},
};
use crate::parser::types::{NetEvent, Protocol, RawEvent};

pub(super) fn parse_event(raw: &RawEvent) -> Option<NetEvent> {
    match raw.event_id {
        EVENT_ID_TCP_CONNECT_IPV4 => parse_connect_v4(raw),
        EVENT_ID_TCP_CONNECT_IPV6 => parse_connect_v6(raw),
        EVENT_ID_TCP_DISCONNECT_IPV4 => parse_disconnect_v4(raw),
        EVENT_ID_TCP_DISCONNECT_IPV6 => parse_disconnect_v6(raw),
        EVENT_ID_TCP_SEND_IPV4 | EVENT_ID_TCP_RETRANSMIT_IPV4 => {
            parse_send_recv_v4(raw, SendRecv::Send, Protocol::Tcp)
        }
        EVENT_ID_TCP_SEND_IPV6 | EVENT_ID_TCP_RETRANSMIT_IPV6 => {
            parse_send_recv_v6(raw, SendRecv::Send, Protocol::Tcp)
        }
        EVENT_ID_TCP_RECV_IPV4 => parse_send_recv_v4(raw, SendRecv::Recv, Protocol::Tcp),
        EVENT_ID_TCP_RECV_IPV6 => parse_send_recv_v6(raw, SendRecv::Recv, Protocol::Tcp),
        EVENT_ID_UDP_SEND_IPV4 => parse_send_recv_v4(raw, SendRecv::Send, Protocol::Udp),
        EVENT_ID_UDP_RECV_IPV4 => parse_send_recv_v4(raw, SendRecv::Recv, Protocol::Udp),
        EVENT_ID_UDP_SEND_IPV6 => parse_send_recv_v6(raw, SendRecv::Send, Protocol::Udp),
        EVENT_ID_UDP_RECV_IPV6 => parse_send_recv_v6(raw, SendRecv::Recv, Protocol::Udp),
        _ => None,
    }
}

fn parse_connect_v4(raw: &RawEvent) -> Option<NetEvent> {
    let fields = parse_v4_fields(&raw.data)?;

    Some(NetEvent::Connect {
        timestamp: raw.timestamp,
        pid: fields.pid,
        proto: Protocol::Tcp,
        src: fields.src,
        dst: fields.dst,
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_connect_v6(raw: &RawEvent) -> Option<NetEvent> {
    let fields = parse_v6_fields(&raw.data)?;

    Some(NetEvent::Connect {
        timestamp: raw.timestamp,
        pid: fields.pid,
        proto: Protocol::Tcp,
        src: fields.src,
        dst: fields.dst,
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_disconnect_v4(raw: &RawEvent) -> Option<NetEvent> {
    let fields = parse_v4_fields(&raw.data)?;

    Some(NetEvent::Disconnect {
        timestamp: raw.timestamp,
        pid: fields.pid,
        proto: Protocol::Tcp,
        src: fields.src,
        dst: fields.dst,
        bytes_out: 0,
        bytes_in: 0,
    })
}

fn parse_disconnect_v6(raw: &RawEvent) -> Option<NetEvent> {
    let fields = parse_v6_fields(&raw.data)?;

    Some(NetEvent::Disconnect {
        timestamp: raw.timestamp,
        pid: fields.pid,
        proto: Protocol::Tcp,
        src: fields.src,
        dst: fields.dst,
        bytes_out: 0,
        bytes_in: 0,
    })
}

/// Tag for send vs recv event construction.
#[derive(Clone, Copy)]
enum SendRecv {
    Send,
    Recv,
}

const fn make_send_recv(
    kind: SendRecv,
    ts: DateTime<Utc>,
    pid: u32,
    proto: Protocol,
    src: String,
    dst: String,
    bytes_out: u64,
    bytes_in: u64,
) -> NetEvent {
    match kind {
        SendRecv::Send => NetEvent::Send {
            timestamp: ts,
            pid,
            proto,
            src,
            dst,
            bytes_out,
            bytes_in,
        },
        SendRecv::Recv => NetEvent::Recv {
            timestamp: ts,
            pid,
            proto,
            src,
            dst,
            bytes_out,
            bytes_in,
        },
    }
}

/// Send/Recv IPv4 share the same layout as connect but produce different variants.
fn parse_send_recv_v4(raw: &RawEvent, kind: SendRecv, proto: Protocol) -> Option<NetEvent> {
    let fields = parse_v4_fields(&raw.data)?;
    let (bytes_out, bytes_in) = bytes_for_direction(kind, fields.size);
    Some(make_send_recv(
        kind,
        raw.timestamp,
        fields.pid,
        proto,
        fields.src,
        fields.dst,
        bytes_out,
        bytes_in,
    ))
}

fn parse_send_recv_v6(raw: &RawEvent, kind: SendRecv, proto: Protocol) -> Option<NetEvent> {
    let fields = parse_v6_fields(&raw.data)?;
    let (bytes_out, bytes_in) = bytes_for_direction(kind, fields.size);
    Some(make_send_recv(
        kind,
        raw.timestamp,
        fields.pid,
        proto,
        fields.src,
        fields.dst,
        bytes_out,
        bytes_in,
    ))
}

const fn bytes_for_direction(kind: SendRecv, size: u32) -> (u64, u64) {
    match kind {
        SendRecv::Send => (size as u64, 0),
        SendRecv::Recv => (0, size as u64),
    }
}
