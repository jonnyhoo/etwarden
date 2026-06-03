//! # `parser::dpi`
//!
//! **Purpose**: Deep Packet Inspection dispatch — detects application-layer protocols
//!   from raw TCP/UDP payloads extracted from NDIS frames.
//! **Public API**: `DpiResult`, `analyze_tcp_payload`, `analyze_udp_payload`
//! **Dependencies**: `parser::dns`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 300 / 350

use serde::Serialize;

use crate::parser::dns::{self, DnsInfo};

// Well-known ports for DPI protocol detection.
const PORT_DNS: u16 = 53;
const PORT_HTTPS: u16 = 443;

/// Result of DPI analysis on a single packet payload.
#[derive(Debug, Clone, Serialize)]
pub enum DpiResult {
    /// DNS query or response detected.
    Dns(DnsInfo),
    /// Plaintext HTTP request or response.
    Http(HttpInfo),
    /// TLS `ClientHello` with extracted SNI.
    Tls(TlsInfo),
}

/// Minimal HTTP information extracted from a plaintext HTTP request/response.
#[derive(Debug, Clone, Serialize)]
pub struct HttpInfo {
    /// Request method (GET, POST, etc.) or `None` for responses.
    pub method: Option<String>,
    /// Request URI path or response status line.
    pub uri_or_status: String,
    /// Host header value if present.
    pub host: Option<String>,
}

/// TLS `ClientHello` information.
#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    /// Server Name Indication hostname extracted from `ClientHello`.
    pub sni: Option<String>,
    /// TLS version string (e.g. "TLS 1.3").
    pub version: Option<String>,
}

/// Analyze a TCP payload for application-layer protocol detection.
///
/// Dispatches to protocol-specific parsers ordered by likelihood and speed.
/// Returns `None` if no known protocol is detected.
#[must_use]
pub fn analyze_tcp_payload(payload: &[u8], src_port: u16, dst_port: u16) -> Option<DpiResult> {
    if payload.is_empty() {
        return None;
    }

    // 1. HTTP detection (fast string prefix matching)
    if let Some(http_info) = analyze_http(payload) {
        return Some(DpiResult::Http(http_info));
    }

    // 2. TLS ClientHello detection (port 443 or handshake signature)
    if src_port == PORT_HTTPS || dst_port == PORT_HTTPS || is_tls_handshake(payload) {
        if let Some(tls_info) = analyze_tls_hello(payload) {
            return Some(DpiResult::Tls(tls_info));
        }
    }

    None
}

/// Analyze a UDP payload for application-layer protocol detection.
#[must_use]
pub fn analyze_udp_payload(payload: &[u8], src_port: u16, dst_port: u16) -> Option<DpiResult> {
    if payload.is_empty() {
        return None;
    }

    // 1. DNS (port 53)
    if src_port == PORT_DNS || dst_port == PORT_DNS {
        if let Some(dns_info) = dns::analyze_dns(payload) {
            return Some(DpiResult::Dns(dns_info));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// HTTP detection
// ---------------------------------------------------------------------------

/// HTTP methods to check for in plaintext traffic.
const HTTP_METHODS: &[&[u8]] = &[
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"HTTP/",
];

/// Detect plaintext HTTP in a TCP payload.
fn analyze_http(payload: &[u8]) -> Option<HttpInfo> {
    // Quick prefix check before expensive parsing.
    let starts_with_method = HTTP_METHODS.iter().any(|m| payload.starts_with(m));
    if !starts_with_method {
        return None;
    }

    // Find end of first line.
    let first_line_end = find_byte(payload, b'\n')?;
    let first_line = &payload[..first_line_end];
    let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);

    if first_line.starts_with(b"HTTP/") {
        // Response: "HTTP/1.1 200 OK"
        let status_line = parse_http_response_line(first_line)?;
        return Some(HttpInfo {
            method: None,
            uri_or_status: status_line,
            host: extract_host_header(payload),
        });
    }

    // Request: "GET /path HTTP/1.1"
    let mut parts = first_line.split(|&b| b == b' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || method.is_empty()
        || uri.is_empty()
        || !HTTP_METHODS[..HTTP_METHODS.len() - 1].contains(&method)
        || !is_http_version_token(version)
    {
        return None;
    }

    Some(HttpInfo {
        method: Some(String::from_utf8_lossy(method).to_string()),
        uri_or_status: String::from_utf8_lossy(uri).to_string(),
        host: extract_host_header(payload),
    })
}

fn parse_http_response_line(first_line: &[u8]) -> Option<String> {
    let mut parts = first_line.splitn(3, |&b| b == b' ');
    let version = parts.next()?;
    let status = parts.next()?;
    if !is_http_version_token(version) || !is_http_status_code(status) {
        return None;
    }
    Some(String::from_utf8_lossy(first_line).to_string())
}

fn is_http_version_token(version: &[u8]) -> bool {
    let Some(rest) = version.strip_prefix(b"HTTP/") else {
        return false;
    };
    let mut dot_seen = false;
    let mut digit_seen = false;
    for &ch in rest {
        match ch {
            b'0'..=b'9' => digit_seen = true,
            b'.' if digit_seen && !dot_seen => dot_seen = true,
            _ => return false,
        }
    }
    digit_seen && dot_seen
}

fn is_http_status_code(status: &[u8]) -> bool {
    status.len() == 3 && status.iter().all(u8::is_ascii_digit)
}

/// Find first occurrence of a byte in a slice (replaces memchr dependency).
fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Extract the Host header value from an HTTP payload.
fn extract_host_header(payload: &[u8]) -> Option<String> {
    let needle = b"Host:";
    let search_end = payload.len().min(4096);
    let window = &payload[..search_end];

    for line in window.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(value) = strip_prefix_ignore_ascii_case(line, needle) else {
            continue;
        };
        let value = value.trim_ascii_start();
        if value.is_empty() {
            return None;
        }
        return Some(String::from_utf8_lossy(value).to_string());
    }

    None
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &input[prefix.len()..])
}

// ---------------------------------------------------------------------------
// TLS ClientHello detection
// ---------------------------------------------------------------------------

/// Check if the payload starts with a TLS record header (content type 22 = Handshake).
fn is_tls_handshake(payload: &[u8]) -> bool {
    // TLS record: ContentType(1) + Version(2) + Length(2) + ...
    if payload.len() < 5 {
        return false;
    }
    // Content type 22 = Handshake
    payload[0] == 0x16
        // Version: 0x0301 (TLS 1.0) or 0x0302 (TLS 1.1) or 0x0303 (TLS 1.2/1.3)
        && payload[1] == 0x03
        && (payload[2] >= 0x01 && payload[2] <= 0x03)
}

/// Parse TLS `ClientHello` to extract SNI and version.
fn analyze_tls_hello(payload: &[u8]) -> Option<TlsInfo> {
    if payload.len() < 43 || !is_tls_handshake(payload) {
        return None;
    }

    // TLS record header: type(1) + version(2) + length(2)
    let record_version = u16::from_be_bytes([payload[1], payload[2]]);
    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    let record_end = checked_end(5, record_len, payload.len())?;

    // Handshake header starts at offset 5
    // HandshakeType(1) should be 0x01 (ClientHello)
    if payload[5] != 0x01 {
        return None;
    }
    let handshake_len =
        (usize::from(payload[6]) << 16) | (usize::from(payload[7]) << 8) | usize::from(payload[8]);
    let handshake_end = checked_end(9, handshake_len, record_end)?;

    // Random: 32 bytes starting at offset 11
    let random_end = 11 + 32;
    if handshake_end <= random_end {
        return None;
    }

    // Session ID length at offset 43
    let session_id_len = payload[random_end] as usize;
    let cipher_suites_start = random_end + 1 + session_id_len;
    if handshake_end <= cipher_suites_start + 1 {
        return None;
    }

    // Cipher suites length (2 bytes)
    let cipher_suites_len = u16::from_be_bytes([
        payload[cipher_suites_start],
        payload[cipher_suites_start + 1],
    ]) as usize;
    let compression_start = cipher_suites_start + 2 + cipher_suites_len;
    if handshake_end <= compression_start + 1 {
        return None;
    }

    // Compression methods length (1 byte)
    let compression_len = payload[compression_start] as usize;
    let extensions_start = compression_start + 1 + compression_len;
    if handshake_end <= extensions_start + 2 {
        return None;
    }

    // Extensions total length (2 bytes)
    let extensions_len =
        u16::from_be_bytes([payload[extensions_start], payload[extensions_start + 1]]) as usize;
    let extensions_end = checked_end(extensions_start + 2, extensions_len, handshake_end)?;
    let mut offset = extensions_start + 2;

    // Walk extensions looking for SNI (type 0x0000)
    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        let ext_data_start = offset + 4;
        let ext_data_end = checked_end(ext_data_start, ext_len, extensions_end)?;

        if ext_type == 0x0000 {
            // SNI extension
            return Some(TlsInfo {
                sni: extract_sni_from_extension(payload, ext_data_start, ext_len),
                version: Some(tls_version_string(record_version)),
            });
        }

        offset = ext_data_end;
    }
    if offset != extensions_end {
        return None;
    }

    // No SNI found but still a valid TLS handshake
    Some(TlsInfo {
        sni: None,
        version: Some(tls_version_string(record_version)),
    })
}

fn checked_end(start: usize, len: usize, limit: usize) -> Option<usize> {
    let end = start.checked_add(len)?;
    (end <= limit).then_some(end)
}

/// Extract the hostname from the SNI extension data.
fn extract_sni_from_extension(
    payload: &[u8],
    ext_data_start: usize,
    ext_len: usize,
) -> Option<String> {
    let ext_end = checked_end(ext_data_start, ext_len, payload.len())?;

    // SNI list length (2 bytes)
    let list_len_end = checked_end(ext_data_start, 2, ext_end)?;
    let list_len = usize::from(u16::from_be_bytes([
        payload[ext_data_start],
        payload[ext_data_start + 1],
    ]));
    let list_end = checked_end(list_len_end, list_len, ext_end)?;
    if list_end != ext_end {
        return None;
    }
    let pos = list_len_end;

    // First entry: type(1) + length(2) + hostname
    checked_end(pos, 3, list_end)?;
    if payload[pos] != 0 {
        return None;
    }
    let entry_len = usize::from(u16::from_be_bytes([payload[pos + 1], payload[pos + 2]]));
    let hostname_start = pos + 3;
    let hostname_end = checked_end(hostname_start, entry_len, list_end)?;

    let hostname = &payload[hostname_start..hostname_end];
    if hostname.is_empty() {
        return None;
    }

    std::str::from_utf8(hostname).ok().map(str::to_string)
}

/// Convert TLS record version bytes to a human-readable string.
fn tls_version_string(version: u16) -> String {
    match version {
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2/1.3".to_string(),
        _ => format!("TLS 0x{version:04x}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_get_detected() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = analyze_http(payload).expect("should detect HTTP");
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.uri_or_status, "/index.html");
        assert_eq!(result.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn http_response_detected() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let result = analyze_http(payload).expect("should detect HTTP response");
        assert!(result.method.is_none());
        assert!(result.uri_or_status.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn http_response_requires_valid_version_and_status() {
        assert!(analyze_http(b"HTTP/1 200 OK\r\n\r\n").is_none());
        assert!(analyze_http(b"HTTP/1.1 OK\r\n\r\n").is_none());
        assert!(analyze_http(b"HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn non_http_returns_none() {
        let payload = b"random binary data that is not HTTP";
        assert!(analyze_http(payload).is_none());
    }

    #[test]
    fn http_request_requires_uri_and_version() {
        assert!(analyze_http(b"GET \r\nHost: example.com\r\n\r\n").is_none());
        assert!(analyze_http(b"GET /\r\nHost: example.com\r\n\r\n").is_none());
    }

    #[test]
    fn http_request_rejects_bad_version() {
        assert!(analyze_http(b"GET / NOTHTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
    }

    #[test]
    fn tls_handshake_detected() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01, 0x00, 0x05]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x01, 0x00, 0x05]));
    }

    #[test]
    fn tls_client_hello_with_sni_detected() {
        let result = analyze_tls_hello(&build_tls_client_hello("example.com"))
            .expect("should parse tls client hello");

        assert_eq!(result.sni.as_deref(), Some("example.com"));
        assert_eq!(result.version.as_deref(), Some("TLS 1.2/1.3"));
    }

    #[test]
    fn tls_rejects_truncated_record_length() {
        let mut payload = build_tls_client_hello("example.com");
        let declared = u16::try_from(payload.len() - 4).expect("fits in u16");
        payload[3..5].copy_from_slice(&declared.to_be_bytes());
        payload.truncate(payload.len() - 2);

        assert!(analyze_tls_hello(&payload).is_none());
    }

    #[test]
    fn tls_rejects_extension_past_declared_length() {
        let mut payload = build_tls_client_hello("example.com");
        let ext_len_offset = 54;
        let declared = u16::from_be_bytes([payload[ext_len_offset], payload[ext_len_offset + 1]]);
        payload[ext_len_offset..ext_len_offset + 2]
            .copy_from_slice(&declared.saturating_add(1).to_be_bytes());

        assert!(analyze_tls_hello(&payload).is_none());
    }

    #[test]
    fn tls_does_not_extract_sni_when_list_length_mismatches() {
        let mut payload = build_tls_client_hello("example.com");
        payload[56..58].copy_from_slice(&1u16.to_be_bytes());

        let result = analyze_tls_hello(&payload).expect("still valid tls");
        assert!(result.sni.is_none());
    }

    #[test]
    fn tls_does_not_extract_non_hostname_sni_entry() {
        let mut payload = build_tls_client_hello("example.com");
        payload[58] = 1;

        let result = analyze_tls_hello(&payload).expect("still valid tls");
        assert!(result.sni.is_none());
    }

    #[test]
    fn tls_does_not_extract_invalid_utf8_sni() {
        let mut payload = build_tls_client_hello("example.com");
        payload[61] = 0xFF;

        let result = analyze_tls_hello(&payload).expect("still valid tls");
        assert!(result.sni.is_none());
    }

    #[test]
    fn dns_udp_dispatch() {
        let pkt = build_test_query("example.com", 1);
        let result = analyze_udp_payload(&pkt, 50234, 53);
        assert!(result.is_some(), "should detect DNS on port 53");
    }

    #[test]
    fn empty_payload_returns_none() {
        assert!(analyze_tcp_payload(&[], 80, 8080).is_none());
        assert!(analyze_udp_payload(&[], 53, 53).is_none());
    }

    #[test]
    fn extract_host_header_case_insensitive() {
        let payload = b"GET / HTTP/1.1\r\nhOsT: Example.COM\r\n\r\n";
        let host = extract_host_header(payload).expect("should find host");
        assert_eq!(host, "Example.COM");
    }

    #[test]
    fn extract_host_header_ignores_uri_host_substring() {
        let payload = b"GET /?x=Host:evil.test HTTP/1.1\r\nUser-Agent: test\r\n\r\n";

        assert!(extract_host_header(payload).is_none());
    }

    #[test]
    fn extract_host_header_ignores_prefixed_header_name() {
        let payload = b"GET / HTTP/1.1\r\nX-Host: evil.test\r\n\r\n";

        assert!(extract_host_header(payload).is_none());
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

    /// Build a minimal DNS query packet for testing.
    fn build_test_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        for label in name.split('.') {
            let bytes = label.as_bytes();
            pkt.push(u8::try_from(bytes.len()).unwrap_or(255));
            pkt.extend_from_slice(bytes);
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt
    }
}
