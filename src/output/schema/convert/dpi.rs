//! # `output::schema::convert::dpi`
//!
//! **Purpose**: Projects attributed application-layer DPI events into stable NDJSON schema lines.
//! **Public API**: module-private DPI projection helpers
//! **Dependencies**: `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 80 / 120

use chrono::{DateTime, Utc};

use crate::output::schema::{HttpEventLine, OutputLine, TlsEventLine};

#[expect(
    clippy::too_many_arguments,
    reason = "HTTP schema projection keeps source fields explicit"
)]
pub(super) fn http_request_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    src: &str,
    dst: &str,
    method: &str,
    path: &str,
    version: &str,
    host: Option<&str>,
    content_type: Option<&str>,
    content_length: Option<u64>,
    process_name: Option<String>,
) -> OutputLine {
    OutputLine::HttpEvent(HttpEventLine {
        timestamp,
        pid,
        event: "http_request".into(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        status_line: None,
        version: version.to_owned(),
        status_code: None,
        host: host.map(str::to_owned),
        content_type: content_type.map(str::to_owned),
        content_length,
        process_name,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "HTTP schema projection keeps source fields explicit"
)]
pub(super) fn http_response_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    src: &str,
    dst: &str,
    status_line: &str,
    version: &str,
    status_code: u16,
    host: Option<&str>,
    content_type: Option<&str>,
    content_length: Option<u64>,
    process_name: Option<String>,
) -> OutputLine {
    OutputLine::HttpEvent(HttpEventLine {
        timestamp,
        pid,
        event: "http_response".into(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        method: None,
        path: None,
        status_line: Some(status_line.to_owned()),
        version: version.to_owned(),
        status_code: Some(status_code),
        host: host.map(str::to_owned),
        content_type: content_type.map(str::to_owned),
        content_length,
        process_name,
    })
}

pub(super) fn tls_hello_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    src: &str,
    dst: &str,
    sni: Option<&str>,
    version: Option<&str>,
    classic_text: &str,
    classic_hash: &str,
    normalized_text: &str,
    normalized_hash: &str,
    sorted_fingerprint: &str,
    original_fingerprint: &str,
    sorted_raw: &str,
    original_raw: &str,
    alpn: &[String],
    cipher_count: usize,
    extension_count: usize,
    process_name: Option<String>,
) -> OutputLine {
    OutputLine::TlsEvent(TlsEventLine {
        timestamp,
        pid,
        event: "tls_hello".into(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        sni: sni.map(str::to_owned),
        tls_version: version.map(str::to_owned),
        ja3: classic_text.to_owned(),
        ja3_hash: classic_hash.to_owned(),
        ja3n: normalized_text.to_owned(),
        ja3n_hash: normalized_hash.to_owned(),
        ja4: sorted_fingerprint.to_owned(),
        ja4o: original_fingerprint.to_owned(),
        ja4r: sorted_raw.to_owned(),
        ja4ro: original_raw.to_owned(),
        alpn: alpn.to_vec(),
        cipher_count,
        extension_count,
        process_name,
    })
}
