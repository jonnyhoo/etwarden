//! # `output::schema::convert`
//!
//! **Purpose**: Converts parser events into stable NDJSON schema lines.
//! **Public API**: `event_to_line`, `event_to_line_enriched`
//! **Dependencies**: `output::schema`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 185 / 240

mod dns;
mod dpi;
mod event;
mod http_payload;
mod network;
mod process;

use process::ProcessFields;

use crate::{output::schema::OutputLine, parser::types::NetEvent, process::ProcessInfo};

/// Converts a `NetEvent` into an `EventLine` for output.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
///
/// # Returns
/// An `OutputLine` ready for NDJSON serialization.
/// Enrichment fields (`scope`, `process_name`) are `None`.
#[must_use]
pub fn event_to_line(event: &NetEvent) -> OutputLine {
    event_to_line_enriched(event, None, None)
}

/// Converts a `NetEvent` into an enriched `OutputLine`.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
/// * `process_name` — Optional resolved process name.
/// * `scope_override` — Optional pre-computed scope label; if `None`,
///   scope is auto-detected from the remote address.
///
/// # Returns
/// An `OutputLine` with enrichment fields populated when available.
#[must_use]
pub fn event_to_line_enriched(
    event: &NetEvent,
    process_name: Option<String>,
    scope_override: Option<String>,
) -> OutputLine {
    event::event_to_line_enriched(
        event,
        ProcessFields::from_name(process_name),
        scope_override,
    )
}

/// Converts a `NetEvent` into an enriched `OutputLine` with process tree metadata.
///
/// # Arguments
/// * `event` — The parsed network event to convert.
/// * `process_info` — Optional resolved process metadata.
/// * `scope_override` — Optional pre-computed scope label; if `None`,
///   scope is auto-detected from the remote address.
///
/// # Returns
/// An `OutputLine` with process enrichment fields populated when available.
#[must_use]
pub fn event_to_line_with_process_info(
    event: &NetEvent,
    process_info: Option<ProcessInfo>,
    scope_override: Option<String>,
) -> OutputLine {
    event::event_to_line_enriched(
        event,
        ProcessFields::from_info(process_info),
        scope_override,
    )
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::{Protocol, RawFrame};

    fn test_timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    #[test]
    fn raw_capture_converts_to_error_line() {
        let event = NetEvent::RawCapture {
            frame: RawFrame {
                timestamp: test_timestamp(),
                data: vec![0xde, 0xad, 0xbe, 0xef],
            },
            pid: 1234,
        };
        let line = event_to_line(&event);
        let OutputLine::Error(line) = line else {
            unreachable!()
        };
        assert_eq!(line.kind, "error");
        assert_eq!(
            line.message,
            "raw capture event cannot be serialized to NDJSON"
        );
    }

    #[test]
    fn event_to_line_converts_connect() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "connect");
        assert_eq!(line.pid, 1234);
    }

    #[test]
    fn event_to_line_converts_disconnect() {
        let event = NetEvent::Disconnect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 512,
            bytes_in: 2048,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "disconnect");
        assert_eq!(line.bytes_out, 512);
    }

    #[test]
    fn enriched_line_includes_scope() {
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "10.0.0.1:49152".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let line = event_to_line_enriched(&event, Some("chrome.exe".into()), None);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.scope, Some("PUBLIC".into()));
        assert_eq!(line.process_name, Some("chrome.exe".into()));
    }

    #[test]
    fn recv_scope_uses_remote_destination() {
        let event = NetEvent::Recv {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Udp,
            src: "10.0.0.2:54321".into(),
            dst: "8.8.8.8:53".into(),
            bytes_out: 0,
            bytes_in: 128,
        };
        let line = event_to_line(&event);
        let OutputLine::Event(line) = line else {
            unreachable!()
        };
        assert_eq!(line.scope, Some("PUBLIC".into()));
    }

    #[test]
    fn dns_query_line_uses_hostname_field() {
        let event = NetEvent::DnsQuery {
            timestamp: test_timestamp(),
            pid: 1234,
            domain: "example.com".into(),
            query_type: 1,
            query_type_name: "A".into(),
        };
        let line = event_to_line(&event);
        let OutputLine::DnsEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.hostname, "example.com");
        assert_eq!(line.event, "dns_query");
        assert_eq!(line.status, None);
    }

    #[test]
    fn dns_response_line_keeps_status_and_ips() {
        let event = NetEvent::DnsResponse {
            timestamp: test_timestamp(),
            pid: 1234,
            domain: "example.com".into(),
            query_type: 1,
            query_type_name: "A".into(),
            status: 0,
            status_name: "NOERROR".into(),
            result_ips: vec!["93.184.216.34".into()],
            truncated: false,
        };
        let line = event_to_line(&event);
        let OutputLine::DnsEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.hostname, "example.com");
        assert_eq!(line.status, Some(0));
        assert_eq!(line.result_ips, vec!["93.184.216.34"]);
        assert!(!line.truncated);
    }

    #[test]
    fn dns_response_line_keeps_truncated_flag() {
        let event = NetEvent::DnsResponse {
            timestamp: test_timestamp(),
            pid: 1234,
            domain: "example.com".into(),
            query_type: 1,
            query_type_name: "A".into(),
            status: 0,
            status_name: "NOERROR".into(),
            result_ips: Vec::new(),
            truncated: true,
        };
        let line = event_to_line(&event);
        let OutputLine::DnsEvent(line) = line else {
            unreachable!()
        };
        assert!(line.truncated);
    }

    #[test]
    fn http_request_line_keeps_method_path_and_host() {
        let event = NetEvent::HttpRequest {
            timestamp: test_timestamp(),
            pid: 1234,
            src: "10.0.0.1:51000".into(),
            dst: "93.184.216.34:80".into(),
            method: "GET".into(),
            path: "/index.html".into(),
            host: Some("example.com".into()),
            version: "HTTP/1.1".into(),
            content_type: None,
            content_length: None,
        };
        let line = event_to_line(&event);
        let OutputLine::HttpEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "http_request");
        assert_eq!(line.method.as_deref(), Some("GET"));
        assert_eq!(line.path.as_deref(), Some("/index.html"));
        assert_eq!(line.host.as_deref(), Some("example.com"));
        assert_eq!(line.version, "HTTP/1.1");
        assert_eq!(line.status_code, None);
    }

    #[test]
    fn http_response_line_keeps_status_and_content_headers() {
        let event = NetEvent::HttpResponse {
            timestamp: test_timestamp(),
            pid: 1234,
            src: "93.184.216.34:80".into(),
            dst: "10.0.0.1:51000".into(),
            status_line: "HTTP/1.1 200 OK".into(),
            host: None,
            version: "HTTP/1.1".into(),
            status_code: 200,
            content_type: Some("application/json".into()),
            content_length: Some(123),
        };
        let line = event_to_line(&event);
        let OutputLine::HttpEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "http_response");
        assert_eq!(line.status_line.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(line.status_code, Some(200));
        assert_eq!(line.content_type.as_deref(), Some("application/json"));
        assert_eq!(line.content_length, Some(123));
    }

    #[test]
    fn tls_hello_line_keeps_sni_and_version() {
        let event = NetEvent::TlsHello {
            timestamp: test_timestamp(),
            pid: 1234,
            src: "10.0.0.1:51000".into(),
            dst: "93.184.216.34:443".into(),
            sni: Some("example.com".into()),
            version: Some("TLS 1.2/1.3".into()),
            ja3: "771,4865,0,,".into(),
            ja3_hash: "hash-ja3".into(),
            ja3n: "771,4865,0,,".into(),
            ja3n_hash: "hash-ja3n".into(),
            ja4: "t13d010100_hash_hash".into(),
            ja4o: "t13d010100_hash_hash".into(),
            ja4r: "t13d010100_1301_0000_".into(),
            ja4ro: "t13d010100_1301_0000_".into(),
            alpn: vec!["h2".into()],
            cipher_count: 15,
            extension_count: 7,
        };
        let line = event_to_line(&event);
        let OutputLine::TlsEvent(line) = line else {
            unreachable!()
        };
        assert_eq!(line.event, "tls_hello");
        assert_eq!(line.sni.as_deref(), Some("example.com"));
        assert_eq!(line.tls_version.as_deref(), Some("TLS 1.2/1.3"));
        assert_eq!(line.ja3, "771,4865,0,,");
        assert_eq!(line.ja4, "t13d010100_hash_hash");
        assert_eq!(line.alpn, vec!["h2"]);
        assert_eq!(line.cipher_count, 15);
        assert_eq!(line.extension_count, 7);
    }
}
