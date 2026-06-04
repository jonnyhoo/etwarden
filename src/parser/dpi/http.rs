//! # `parser::dpi::http`
//!
//! **Purpose**: Detects plaintext HTTP request/response metadata.
//! **Public API**: `HttpInfo`
//! **Dependencies**: `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 135 / 190

use serde::Serialize;

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

const HTTP_METHODS: &[&[u8]] = &[
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"HTTP/",
];

/// Detect plaintext HTTP in a TCP payload.
pub(super) fn analyze_http(payload: &[u8]) -> Option<HttpInfo> {
    let starts_with_method = HTTP_METHODS
        .iter()
        .any(|method| payload.starts_with(method));
    if !starts_with_method {
        return None;
    }

    let first_line_end = find_byte(payload, b'\n')?;
    let first_line = &payload[..first_line_end];
    let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);

    if first_line.starts_with(b"HTTP/") {
        let status_line = parse_http_response_line(first_line)?;
        return Some(HttpInfo {
            method: None,
            uri_or_status: status_line,
            host: extract_host_header(payload),
        });
    }

    let mut parts = first_line.split(|&byte| byte == b' ');
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
        method: Some(http_token_to_string(method)?),
        uri_or_status: http_visible_utf8(uri)?,
        host: extract_host_header(payload),
    })
}

fn parse_http_response_line(first_line: &[u8]) -> Option<String> {
    let mut parts = first_line.splitn(3, |&byte| byte == b' ');
    let version = parts.next()?;
    let status = parts.next()?;
    if !is_http_version_token(version) || !is_http_status_code(status) {
        return None;
    }
    http_visible_utf8(first_line)
}

fn is_http_version_token(version: &[u8]) -> bool {
    let Some(rest) = version.strip_prefix(b"HTTP/") else {
        return false;
    };
    let Some(dot) = rest.iter().position(|&ch| ch == b'.') else {
        return false;
    };
    let major = &rest[..dot];
    let minor = &rest[dot + 1..];

    if major.is_empty() || minor.is_empty() {
        return false;
    }
    major.iter().all(u8::is_ascii_digit) && minor.iter().all(u8::is_ascii_digit)
}

fn is_http_status_code(status: &[u8]) -> bool {
    status.len() == 3 && status.iter().all(u8::is_ascii_digit)
}

fn http_token_to_string(value: &[u8]) -> Option<String> {
    std::str::from_utf8(value).ok().map(str::to_string)
}

fn http_visible_utf8(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    (!text.bytes().any(|byte| byte.is_ascii_control())).then(|| text.to_string())
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&byte| byte == needle)
}

fn extract_host_header(payload: &[u8]) -> Option<String> {
    let needle = b"Host:";
    let search_end = payload.len().min(4096);
    let window = &payload[..search_end];

    for line in window.split(|&byte| byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(value) = strip_prefix_ignore_ascii_case(line, needle) else {
            continue;
        };
        let value = value.trim_ascii();
        if value.is_empty() {
            return None;
        }
        return http_visible_utf8(value);
    }

    None
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &input[prefix.len()..])
}

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
        assert!(analyze_http(b"HTTP/1. 200 OK\r\n\r\n").is_none());
        assert!(analyze_http(b"HTTP/1.1. 200 OK\r\n\r\n").is_none());
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
        assert!(analyze_http(b"GET / HTTP/1.\r\nHost: example.com\r\n\r\n").is_none());
    }

    #[test]
    fn http_rejects_invalid_utf8_and_control_output() {
        assert!(analyze_http(b"GET /\xFF HTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
        assert!(analyze_http(b"GET /\x7F HTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
        assert!(analyze_http(b"HTTP/1.1 200 O\xFFK\r\n\r\n").is_none());
        assert!(analyze_http(b"HTTP/1.1 200 O\x00K\r\n\r\n").is_none());
        assert!(extract_host_header(b"GET / HTTP/1.1\r\nHost: ex\xFFample.com\r\n\r\n").is_none());
        assert!(extract_host_header(b"GET / HTTP/1.1\r\nHost: ex\x00ample.com\r\n\r\n").is_none());
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
}
