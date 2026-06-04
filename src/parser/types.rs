//! # `parser::types`
//!
//! **Purpose**: Core type definitions for ETW event parsing — pure types, no ETW imports.
//! **Public API**: `enum Protocol`, `struct FiveTuple`, `enum NetEvent`, `struct RawEvent`,
//!   `struct RawFrame`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 340 / 400

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
    /// Raw frame from NDIS provider — routed to pcap sink, not NDJSON.
    RawCapture { frame: RawFrame, pid: u32 },
    /// DNS query observed from an attributed ETW source.
    DnsQuery {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        domain: String,
        query_type: u16,
        query_type_name: String,
    },
    /// DNS response observed from an attributed ETW source.
    DnsResponse {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        domain: String,
        query_type: u16,
        query_type_name: String,
        status: u32,
        status_name: String,
        result_ips: Vec<String>,
        truncated: bool,
    },
    /// Plaintext HTTP request observed from an attributed TCP packet.
    HttpRequest {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        src: String,
        dst: String,
        method: String,
        path: String,
        host: Option<String>,
    },
    /// Plaintext HTTP response observed from an attributed TCP packet.
    HttpResponse {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        src: String,
        dst: String,
        status_line: String,
        host: Option<String>,
    },
    /// TLS `ClientHello` metadata observed from an attributed TCP packet.
    TlsHello {
        #[serde(rename = "t")]
        timestamp: DateTime<Utc>,
        pid: u32,
        src: String,
        dst: String,
        sni: Option<String>,
        version: Option<String>,
    },
}

impl NetEvent {
    /// Returns the `bytes_out` field from any variant.
    #[must_use]
    pub const fn bytes_out(&self) -> u64 {
        match self {
            Self::Connect { bytes_out, .. }
            | Self::Disconnect { bytes_out, .. }
            | Self::Send { bytes_out, .. }
            | Self::Recv { bytes_out, .. } => *bytes_out,
            Self::RawCapture { .. }
            | Self::DnsQuery { .. }
            | Self::DnsResponse { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponse { .. }
            | Self::TlsHello { .. } => 0,
        }
    }

    /// Returns the `pid` field from any variant.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        match self {
            Self::Connect { pid, .. }
            | Self::Disconnect { pid, .. }
            | Self::Send { pid, .. }
            | Self::Recv { pid, .. }
            | Self::RawCapture { pid, .. }
            | Self::DnsQuery { pid, .. }
            | Self::DnsResponse { pid, .. }
            | Self::HttpRequest { pid, .. }
            | Self::HttpResponse { pid, .. }
            | Self::TlsHello { pid, .. } => *pid,
        }
    }

    /// Returns the `bytes_in` field from any variant.
    #[must_use]
    pub const fn bytes_in(&self) -> u64 {
        match self {
            Self::Connect { bytes_in, .. }
            | Self::Disconnect { bytes_in, .. }
            | Self::Send { bytes_in, .. }
            | Self::Recv { bytes_in, .. } => *bytes_in,
            Self::RawCapture { .. }
            | Self::DnsQuery { .. }
            | Self::DnsResponse { .. }
            | Self::HttpRequest { .. }
            | Self::HttpResponse { .. }
            | Self::TlsHello { .. } => 0,
        }
    }
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
#[derive(Debug, Clone, Serialize)]
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
