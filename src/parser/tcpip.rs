//! # `parser::tcpip`
//!
//! **Purpose**: Parses Microsoft-Windows-Kernel-Network TCP/UDP ETW events into `NetEvent`.
//! **Public API**: `struct TcpIpParser` (implements `EventParser`)
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 350 / 400

mod events;
mod fields;

use windows::core::GUID;

use crate::parser::{
    tcpip::events::parse_event,
    types::{NetEvent, RawEvent},
    EventParser,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Microsoft-Windows-Kernel-Network provider GUID.
pub const PROVIDER_TCPIP: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

// Event IDs from the Microsoft-Windows-Kernel-Network manifest.
pub const EVENT_ID_TCP_SEND_IPV4: u16 = 10;
pub const EVENT_ID_TCP_RECV_IPV4: u16 = 11;
pub const EVENT_ID_TCP_CONNECT_IPV4: u16 = 12;
pub const EVENT_ID_TCP_DISCONNECT_IPV4: u16 = 13;
pub const EVENT_ID_TCP_RETRANSMIT_IPV4: u16 = 14;
pub const EVENT_ID_TCP_ESTABLISHED_IPV4: u16 = 15;
pub const EVENT_ID_TCP_SEND_IPV6: u16 = 26;
pub const EVENT_ID_TCP_RECV_IPV6: u16 = 27;
pub const EVENT_ID_TCP_CONNECT_IPV6: u16 = 28;
pub const EVENT_ID_TCP_DISCONNECT_IPV6: u16 = 29;
pub const EVENT_ID_TCP_RETRANSMIT_IPV6: u16 = 30;
pub const EVENT_ID_TCP_ESTABLISHED_IPV6: u16 = 31;
pub const EVENT_ID_UDP_SEND_IPV4: u16 = 42;
pub const EVENT_ID_UDP_RECV_IPV4: u16 = 43;
pub const EVENT_ID_UDP_SEND_IPV6: u16 = 58;
pub const EVENT_ID_UDP_RECV_IPV6: u16 = 59;

// ---------------------------------------------------------------------------
// TcpIpParser
// ---------------------------------------------------------------------------

/// Parses ETW events from the Microsoft-Windows-Kernel-Network provider.
///
/// Handles TCP connect/disconnect/send/recv and UDP send/recv events.
/// The raw event `data` buffer is parsed at fixed offsets matching the
/// TCPIP ETW manifest layout.
pub struct TcpIpParser;

impl EventParser for TcpIpParser {
    fn provider_guid(&self) -> GUID {
        GUID::from(PROVIDER_TCPIP)
    }

    fn parse(&self, raw: &RawEvent) -> Option<NetEvent> {
        parse_event(raw)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::{NetEvent, Protocol};

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-06-15T12:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    fn raw_v4(event_id: u16, pid: u32, extra: &[u8]) -> RawEvent {
        let mut data = Vec::new();
        data.extend_from_slice(&pid.to_ne_bytes()); // offset 0: PID
        data.extend_from_slice(&42u32.to_ne_bytes()); // offset 4: size
                                                      // daddr = 127.0.0.1 (network bytes 7f 00 00 01, LE u32 = 0x0100007f)
        data.extend_from_slice(&0x0100_007fu32.to_ne_bytes());
        // saddr = 192.168.1.1 (network bytes c0 a8 01 01, LE u32 = 0x0101a8c0)
        data.extend_from_slice(&0x0101_a8c0u32.to_ne_bytes());
        data.extend_from_slice(&443u16.to_be_bytes()); // offset 16: dport = 443
        data.extend_from_slice(&4802u16.to_be_bytes()); // offset 18: sport = 4802
        data.extend_from_slice(extra);
        RawEvent {
            event_id,
            pid,
            timestamp: ts(),
            data,
        }
    }

    fn raw_v6(event_id: u16, pid: u32) -> RawEvent {
        let mut data = Vec::new();
        data.extend_from_slice(&pid.to_ne_bytes()); // offset 0: PID
        data.extend_from_slice(&0u32.to_ne_bytes()); // offset 4: size
                                                     // offset 8-23: daddr (::1)
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // offset 24-39: saddr (fe80::1)
        data.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&443u16.to_be_bytes()); // offset 40: dport = 443
        data.extend_from_slice(&4802u16.to_be_bytes()); // offset 42: sport = 4802
        data.extend_from_slice(&0u64.to_ne_bytes()); // offset 44: conn_id
        RawEvent {
            event_id,
            pid,
            timestamp: ts(),
            data,
        }
    }

    #[test]
    fn provider_guid_matches() {
        let parser = TcpIpParser;
        assert_eq!(parser.provider_guid(), GUID::from(PROVIDER_TCPIP));
    }

    #[test]
    fn parse_connect_v4() {
        let raw = raw_v4(EVENT_ID_TCP_CONNECT_IPV4, 1234, &[0u8; 8]);
        let event = TcpIpParser.parse(&raw).expect("should parse connect v4");
        let NetEvent::Connect {
            pid,
            proto,
            src,
            dst,
            ..
        } = event
        else {
            unreachable!("expected Connect variant");
        };
        assert_eq!(pid, 1234);
        assert_eq!(proto, Protocol::Tcp);
        assert!(src.contains(":4802"), "src={src}");
        assert!(dst.contains(":443"), "dst={dst}");
    }

    #[test]
    fn parse_connect_v6() {
        let raw = raw_v6(EVENT_ID_TCP_CONNECT_IPV6, 5678);
        let event = TcpIpParser.parse(&raw).expect("should parse connect v6");
        let NetEvent::Connect {
            pid,
            proto,
            src,
            dst,
            ..
        } = event
        else {
            unreachable!("expected Connect variant");
        };
        assert_eq!(pid, 5678);
        assert_eq!(proto, Protocol::Tcp);
        assert_eq!(src, "[fe80::1]:4802");
        assert_eq!(dst, "[::1]:443");
    }

    #[test]
    fn parse_disconnect_v4() {
        let raw = raw_v4(EVENT_ID_TCP_DISCONNECT_IPV4, 1234, &[]);
        let event = TcpIpParser.parse(&raw).expect("should parse disconnect v4");
        let NetEvent::Disconnect { pid, .. } = event else {
            unreachable!("expected Disconnect variant");
        };
        assert_eq!(pid, 1234);
    }

    #[test]
    fn parse_disconnect_v6() {
        let raw = raw_v6(EVENT_ID_TCP_DISCONNECT_IPV6, 5678);
        let event = TcpIpParser.parse(&raw).expect("should parse disconnect v6");
        let NetEvent::Disconnect { pid, .. } = event else {
            unreachable!("expected Disconnect variant");
        };
        assert_eq!(pid, 5678);
    }

    #[test]
    fn parse_send_v4() {
        let raw = raw_v4(EVENT_ID_TCP_SEND_IPV4, 999, &[]);
        let event = TcpIpParser.parse(&raw).expect("should parse send v4");
        let NetEvent::Send { pid, bytes_out, .. } = event else {
            unreachable!("expected Send variant");
        };
        assert_eq!(pid, 999);
        assert_eq!(bytes_out, 42);
    }

    #[test]
    fn parse_recv_v4() {
        let raw = raw_v4(EVENT_ID_TCP_RECV_IPV4, 888, &[]);
        let event = TcpIpParser.parse(&raw).expect("should parse recv v4");
        let NetEvent::Recv { pid, bytes_in, .. } = event else {
            unreachable!("expected Recv variant");
        };
        assert_eq!(pid, 888);
        assert_eq!(bytes_in, 42);
    }

    #[test]
    fn parse_send_v6() {
        let raw = raw_v6(EVENT_ID_TCP_SEND_IPV6, 777);
        let event = TcpIpParser.parse(&raw).expect("should parse send v6");
        let NetEvent::Send { pid, .. } = event else {
            unreachable!("expected Send variant");
        };
        assert_eq!(pid, 777);
    }

    #[test]
    fn parse_recv_v6() {
        let raw = raw_v6(EVENT_ID_TCP_RECV_IPV6, 666);
        let event = TcpIpParser.parse(&raw).expect("should parse recv v6");
        let NetEvent::Recv { pid, .. } = event else {
            unreachable!("expected Recv variant");
        };
        assert_eq!(pid, 666);
    }

    #[test]
    fn unknown_event_id_returns_none() {
        let raw = RawEvent {
            event_id: 99,
            pid: 1,
            timestamp: ts(),
            data: vec![0; 28],
        };
        assert!(TcpIpParser.parse(&raw).is_none());
    }

    #[test]
    fn truncated_buffer_returns_none() {
        let raw = RawEvent {
            event_id: EVENT_ID_TCP_CONNECT_IPV4,
            pid: 1,
            timestamp: ts(),
            data: vec![0; 10], // too short
        };
        assert!(TcpIpParser.parse(&raw).is_none());
    }

    #[test]
    fn parser_uses_payload_pid_instead_of_record_pid() {
        let mut raw = raw_v4(EVENT_ID_TCP_SEND_IPV4, 4321, &[]);
        raw.pid = 9999;

        let event = TcpIpParser.parse(&raw).expect("should parse send v4");
        let NetEvent::Send { pid, .. } = event else {
            unreachable!("expected Send variant");
        };

        assert_eq!(pid, 4321);
    }

    #[test]
    fn fmt_ipv6_rejects_wrong_length() {
        assert!(fields::fmt_ipv6(&[0; 15]).is_none());
    }
}
