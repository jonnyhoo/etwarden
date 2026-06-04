//! # `parser::ndis`
//!
//! **Purpose**: Converts Microsoft-Windows-NDIS-PacketCapture ETW frames into attributed network events.
//! **Public API**: `struct NdisParser`, `normalize_frame`
//! **Dependencies**: `parser::dns_codes`, `parser::dpi`, `parser::types`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 190 / 260

mod frame;
mod packet;
#[cfg(test)]
mod test_support;

use std::sync::Arc;

use chrono::{DateTime, Utc};
pub(crate) use frame::normalize_frame;
use packet::extract_packet;
use windows::core::GUID;

use crate::{
    parser::{
        dns_codes::{dns_status_name, dns_type_name},
        dpi::{self, DpiResult},
        endpoint::format_addr_port,
        types::{NetEvent, Protocol, RawEvent, RawFrame},
        EventParser,
    },
    pcap::correlator::Correlator,
};

/// Microsoft-Windows-NDIS-PacketCapture provider GUID.
pub const PROVIDER_NDIS: &str = "2ED6006E-4729-4609-B423-3EE7BCD678EF";

/// Parses ETW events from the Microsoft-Windows-NDIS-PacketCapture provider.
///
/// Each event contains a normalized Ethernet frame. The parser emits `RawCapture`
/// only when the frame has a TCP/UDP five-tuple that resolves through the shared
/// `Correlator`.
pub struct NdisParser {
    correlator: Arc<Correlator>,
}

impl NdisParser {
    /// Creates a new `NdisParser` with the given correlator for PID resolution.
    #[must_use]
    pub const fn new(correlator: Arc<Correlator>) -> Self {
        Self { correlator }
    }

    /// Parses an attributed DNS event from the raw frame payload.
    #[must_use]
    pub fn parse_dns_event(&self, raw: &RawEvent) -> Option<NetEvent> {
        parse_dns_event(&raw.data, raw.timestamp, &self.correlator)
    }

    /// Parses attributed application-layer DPI events from the raw frame payload.
    #[must_use]
    pub fn parse_dpi_event(&self, raw: &RawEvent) -> Option<NetEvent> {
        parse_dpi_event(&raw.data, raw.timestamp, &self.correlator)
    }
}

/// Builds a per-process DNS event from a captured frame.
pub(crate) fn parse_dns_event(
    frame: &[u8],
    timestamp: DateTime<Utc>,
    correlator: &Correlator,
) -> Option<NetEvent> {
    let packet = extract_packet(frame)?;
    if packet.tuple.protocol != Protocol::Udp {
        return None;
    }

    let pid = correlator.resolve_pid(&packet.tuple)?;
    let DpiResult::Dns(info) =
        dpi::analyze_udp_payload(packet.payload, packet.tuple.src_port, packet.tuple.dst_port)?
    else {
        return None;
    };

    let domain = info.query_name?;
    let query_type = info.query_type?.code();
    let query_type_name = dns_type_name(query_type).to_string();

    if info.is_response {
        let status = info.response_code.unwrap_or(0);
        Some(NetEvent::DnsResponse {
            timestamp,
            pid,
            domain,
            query_type,
            query_type_name,
            status,
            status_name: dns_status_name(status).to_string(),
            truncated: info.truncated,
            result_ips: info
                .response_ips
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
        })
    } else {
        Some(NetEvent::DnsQuery {
            timestamp,
            pid,
            domain,
            query_type,
            query_type_name,
        })
    }
}

/// Builds a per-process HTTP/TLS event from a captured TCP frame.
pub(crate) fn parse_dpi_event(
    frame: &[u8],
    timestamp: DateTime<Utc>,
    correlator: &Correlator,
) -> Option<NetEvent> {
    let packet = extract_packet(frame)?;
    if packet.tuple.protocol != Protocol::Tcp {
        return None;
    }

    let pid = correlator.resolve_pid(&packet.tuple)?;
    let src = format_addr_port(&packet.tuple.src_ip, packet.tuple.src_port);
    let dst = format_addr_port(&packet.tuple.dst_ip, packet.tuple.dst_port);

    match dpi::analyze_tcp_payload(packet.payload, packet.tuple.src_port, packet.tuple.dst_port)? {
        DpiResult::Http(info) => {
            let dpi::HttpInfo {
                method,
                uri_or_status,
                host,
            } = info;
            if let Some(method) = method {
                Some(NetEvent::HttpRequest {
                    timestamp,
                    pid,
                    src,
                    dst,
                    method,
                    path: uri_or_status,
                    host,
                })
            } else {
                Some(NetEvent::HttpResponse {
                    timestamp,
                    pid,
                    src,
                    dst,
                    status_line: uri_or_status,
                    host,
                })
            }
        }
        DpiResult::Tls(info) => Some(NetEvent::TlsHello {
            timestamp,
            pid,
            src,
            dst,
            sni: info.sni,
            version: info.version,
            alpn: info.alpn,
            cipher_count: info.cipher_count,
            extension_count: info.extension_count,
        }),
        DpiResult::Dns(_) => None,
    }
}

impl EventParser for NdisParser {
    fn provider_guid(&self) -> GUID {
        GUID::from(PROVIDER_NDIS)
    }

    fn parse(&self, raw: &RawEvent) -> Option<NetEvent> {
        let packet = extract_packet(&raw.data)?;
        let pid = self.correlator.resolve_pid(&packet.tuple)?;
        let frame = RawFrame {
            timestamp: raw.timestamp,
            data: raw.data.clone(),
        };

        Some(NetEvent::RawCapture { frame, pid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{
        ndis::test_support::{
            build_dns_query, build_dns_response_a, build_ethernet_ipv4_tcp,
            build_ethernet_ipv4_tcp_payload, build_ethernet_ipv4_udp,
            build_ethernet_ipv4_udp_with_ips, build_ethernet_ipv6_udp, raw_ndis, ts,
        },
        types::FiveTuple,
    };

    #[test]
    fn provider_guid_matches() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let expected: GUID = GUID::from(PROVIDER_NDIS);
        assert_eq!(parser.provider_guid(), expected);
    }

    #[test]
    fn parse_ipv4_tcp_frame() {
        let corr = Arc::new(Correlator::new());
        let tuple = FiveTuple {
            src_ip: "10.0.0.1".into(),
            src_port: 1234,
            dst_ip: "10.0.0.2".into(),
            dst_port: 80,
            protocol: Protocol::Tcp,
        };
        corr.register_connection(42, tuple);

        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp(10);
        let raw = raw_ndis(frame.clone());

        let event = parser.parse(&raw).expect("should parse");
        match event {
            NetEvent::RawCapture { frame: f, pid } => {
                assert_eq!(pid, 42);
                assert_eq!(f.data, frame);
                assert_eq!(f.timestamp, ts());
            }
            _ => unreachable!("expected RawCapture"),
        }
    }

    #[test]
    fn parse_ipv6_udp_frame() {
        let corr = Arc::new(Correlator::new());
        let tuple = FiveTuple {
            src_ip: "::1".into(),
            src_port: 5678,
            dst_ip: "::1".into(),
            dst_port: 443,
            protocol: Protocol::Udp,
        };
        corr.register_connection(77, tuple);

        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv6_udp(10);
        let raw = raw_ndis(frame.clone());

        let event = parser.parse(&raw).expect("should parse");
        match event {
            NetEvent::RawCapture { frame: f, pid } => {
                assert_eq!(pid, 77);
                assert_eq!(f.data, frame);
            }
            _ => unreachable!("expected RawCapture"),
        }
    }

    #[test]
    fn parse_dns_query_from_udp_frame() {
        let corr = Arc::new(Correlator::new());
        corr.register_connection(
            42,
            FiveTuple {
                src_ip: "10.0.0.1".into(),
                src_port: 53000,
                dst_ip: "8.8.8.8".into(),
                dst_port: 53,
                protocol: Protocol::Udp,
            },
        );
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_udp(&build_dns_query("example.com", 1), 53000, 53);
        let raw = raw_ndis(frame);

        let event = parser.parse_dns_event(&raw).expect("dns event");
        let NetEvent::DnsQuery {
            pid,
            domain,
            query_type,
            ..
        } = event
        else {
            unreachable!("expected DNS query")
        };
        assert_eq!(pid, 42);
        assert_eq!(domain, "example.com");
        assert_eq!(query_type, 1);
    }

    #[test]
    fn parse_dns_response_from_udp_frame() {
        let corr = Arc::new(Correlator::new());
        corr.register_connection(
            42,
            FiveTuple {
                src_ip: "10.0.0.1".into(),
                src_port: 53000,
                dst_ip: "8.8.8.8".into(),
                dst_port: 53,
                protocol: Protocol::Udp,
            },
        );
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_udp_with_ips(
            &build_dns_response_a("example.com", [93, 184, 216, 34]),
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            53,
            53000,
        );
        let raw = raw_ndis(frame);

        let event = parser.parse_dns_event(&raw).expect("dns event");
        let NetEvent::DnsResponse {
            pid,
            domain,
            status,
            result_ips,
            truncated,
            ..
        } = event
        else {
            unreachable!("expected DNS response")
        };
        assert_eq!(pid, 42);
        assert_eq!(domain, "example.com");
        assert_eq!(status, 0);
        assert!(!truncated);
        assert_eq!(result_ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn parse_dns_requires_pid_correlation() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_udp(&build_dns_query("example.com", 1), 53000, 53);
        let raw = raw_ndis(frame);
        assert!(parser.parse_dns_event(&raw).is_none());
    }

    #[test]
    fn parse_http_request_from_tcp_frame() {
        let corr = Arc::new(Correlator::new());
        corr.register_connection(
            42,
            FiveTuple {
                src_ip: "10.0.0.1".into(),
                src_port: 51000,
                dst_ip: "10.0.0.2".into(),
                dst_port: 80,
                protocol: Protocol::Tcp,
            },
        );
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp_payload(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            51000,
            80,
        );
        let raw = raw_ndis(frame);

        let event = parser.parse_dpi_event(&raw).expect("http event");
        let NetEvent::HttpRequest {
            pid,
            method,
            path,
            host,
            src,
            dst,
            ..
        } = event
        else {
            unreachable!("expected HTTP request")
        };
        assert_eq!(pid, 42);
        assert_eq!(method, "GET");
        assert_eq!(path, "/index.html");
        assert_eq!(host.as_deref(), Some("example.com"));
        assert_eq!(src, "10.0.0.1:51000");
        assert_eq!(dst, "10.0.0.2:80");
    }

    #[test]
    fn parse_tls_hello_from_tcp_frame() {
        let corr = Arc::new(Correlator::new());
        corr.register_connection(
            42,
            FiveTuple {
                src_ip: "10.0.0.1".into(),
                src_port: 51000,
                dst_ip: "10.0.0.2".into(),
                dst_port: 443,
                protocol: Protocol::Tcp,
            },
        );
        let parser = NdisParser::new(corr);
        let frame =
            build_ethernet_ipv4_tcp_payload(&build_tls_client_hello("example.com"), 51000, 443);
        let raw = raw_ndis(frame);

        let event = parser.parse_dpi_event(&raw).expect("tls event");
        let NetEvent::TlsHello {
            pid, sni, version, ..
        } = event
        else {
            unreachable!("expected TLS hello")
        };
        assert_eq!(pid, 42);
        assert_eq!(sni.as_deref(), Some("example.com"));
        assert_eq!(version.as_deref(), Some("TLS 1.2"));
    }

    #[test]
    fn parse_dpi_requires_pid_correlation() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp_payload(b"GET / HTTP/1.1\r\n\r\n", 51000, 80);
        let raw = raw_ndis(frame);

        assert!(parser.parse_dpi_event(&raw).is_none());
    }

    #[test]
    fn unknown_correlation_is_not_emitted() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let frame = build_ethernet_ipv4_tcp(10);
        let raw = raw_ndis(frame);

        assert!(parser.parse(&raw).is_none());
    }

    #[test]
    fn truncated_frame_is_not_emitted() {
        let corr = Arc::new(Correlator::new());
        let parser = NdisParser::new(corr);
        let raw = raw_ndis(vec![0x00; 5]);

        assert!(parser.parse(&raw).is_none());
    }

    fn build_tls_client_hello(host: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&[0x00, 0x00]);
        sni.push(0x00);
        sni.extend_from_slice(
            &u16::try_from(host.len())
                .expect("host length fits")
                .to_be_bytes(),
        );
        sni.extend_from_slice(host.as_bytes());
        let list_len = u16::try_from(sni.len() - 2)
            .expect("sni list length fits")
            .to_be_bytes();
        sni[0..2].copy_from_slice(&list_len);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(
            &u16::try_from(sni.len())
                .expect("sni length fits")
                .to_be_bytes(),
        );
        extensions.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("extensions length fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut payload = vec![0x16, 0x03, 0x03];
        let record_len = 4 + body.len();
        payload.extend_from_slice(
            &u16::try_from(record_len)
                .expect("record length fits")
                .to_be_bytes(),
        );
        payload.push(0x01);
        let handshake_len = u32::try_from(body.len()).expect("handshake length fits");
        payload.extend_from_slice(&handshake_len.to_be_bytes()[1..4]);
        payload.extend_from_slice(&body);
        payload
    }
}
