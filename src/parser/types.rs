//! # `parser::types`
//!
//! **Purpose**: Core type definitions for ETW event parsing — pure types, no ETW imports.
//! **Public API**: `struct RawEvent`, `struct RawFrame`, `enum NetEvent`, `enum Protocol`,
//!   `struct FiveTuple`, `struct Timestamp`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 148 / 200

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Network protocol observed in a `NetEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A 5-tuple identifying a network connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FiveTuple {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: Protocol,
}

/// A single parsed network event produced by the TCPIP ETW provider.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum NetEvent {
    Connect {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    Disconnect {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    Send {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
    Recv {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        proto: Protocol,
        src: String,
        dst: String,
        bytes_out: u64,
        bytes_in: u64,
    },
}

/// Unparsed bytes and metadata received in an ETW callback.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub event_id: u16,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub data: Vec<u8>,
}

/// Raw Ethernet frame bytes captured by the NDIS ETW provider.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub timestamp: DateTime<Utc>,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    #[test]
    fn protocol_serializes_uppercase() {
        let json = serde_json::to_string(&Protocol::Tcp).expect("serialize");
        assert_eq!(json, "\"TCP\"");
        let json = serde_json::to_string(&Protocol::Udp).expect("serialize");
        assert_eq!(json, "\"UDP\"");
    }

    #[test]
    fn five_tuple_equality_and_hash() {
        let a = FiveTuple {
            src_ip: "192.168.1.1".into(),
            src_port: 50234,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            protocol: Protocol::Tcp,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn net_event_connect_serializes() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"event\":\"connect\""), "actual: {json}");
        assert!(json.contains("\"pid\":1234"), "actual: {json}");
        assert!(json.contains("\"proto\":\"TCP\""), "actual: {json}");
    }

    #[test]
    fn net_event_disconnect_serializes() {
        let event = NetEvent::Disconnect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 512,
            bytes_in: 2048,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"event\":\"disconnect\""), "actual: {json}");
        assert!(json.contains("\"bytes_out\":512"), "actual: {json}");
    }

    #[test]
    fn net_event_send_serializes() {
        let event = NetEvent::Send {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 100,
            bytes_in: 0,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"event\":\"send\""), "actual: {json}");
    }

    #[test]
    fn net_event_recv_serializes() {
        let event = NetEvent::Recv {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Udp,
            src: "93.184.216.34:443".into(),
            dst: "192.168.1.1:50234".into(),
            bytes_out: 0,
            bytes_in: 200,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"event\":\"recv\""), "actual: {json}");
        assert!(json.contains("\"UDP\""), "actual: {json}");
    }

    #[test]
    fn raw_event_fields() {
        let raw = RawEvent {
            event_id: 10,
            pid: 5678,
            timestamp: test_timestamp(),
            data: vec![1, 2, 3],
        };
        assert_eq!(raw.event_id, 10);
        assert_eq!(raw.pid, 5678);
        assert_eq!(raw.data.len(), 3);
    }

    #[test]
    fn raw_frame_fields() {
        let frame = RawFrame {
            timestamp: test_timestamp(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(frame.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
