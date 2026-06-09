//! # `output::schema::convert::dpi`
//!
//! **Purpose**: Projects attributed application-layer DPI events into stable NDJSON schema lines.
//! **Public API**: module-private DPI projection helpers
//! **Dependencies**: `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 102 / 150

use chrono::{DateTime, Utc};

use super::{http_payload::project_http_payload, process::ProcessFields};
use crate::output::schema::{HttpEventLine, OutputLine, TlsEventLine, TunnelDataEventLine};

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
    headers_base64: Option<&str>,
    headers_truncated: bool,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    let payload = project_http_payload(headers_base64, None, false, content_type);
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
        headers_base64: headers_base64.map(str::to_owned),
        headers: payload.headers,
        headers_truncated,
        status_code: None,
        host: host.map(str::to_owned),
        content_type: content_type.map(str::to_owned),
        content_length,
        decrypted: false,
        content_encoding: None,
        decoded: false,
        body_base64: None,
        body_format: payload.body_format,
        body_text: payload.body_text,
        body_json: payload.body_json,
        sse_events: payload.sse_events,
        body_truncated: false,
        process_name: name,
        ppid,
        command_line,
        tree_path,
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
    headers_base64: Option<&str>,
    headers_truncated: bool,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    let payload = project_http_payload(headers_base64, None, false, content_type);
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
        headers_base64: headers_base64.map(str::to_owned),
        headers: payload.headers,
        headers_truncated,
        status_code: Some(status_code),
        host: host.map(str::to_owned),
        content_type: content_type.map(str::to_owned),
        content_length,
        decrypted: false,
        content_encoding: None,
        decoded: false,
        body_base64: None,
        body_format: payload.body_format,
        body_text: payload.body_text,
        body_json: payload.body_json,
        sse_events: payload.sse_events,
        body_truncated: false,
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "decrypted HTTP schema projection keeps source fields explicit"
)]
pub(super) fn decrypted_http_request_line(
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
    headers_base64: Option<&str>,
    headers_truncated: bool,
    content_encoding: Option<&str>,
    decoded: bool,
    body_base64: Option<&str>,
    body_truncated: bool,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    let payload = project_http_payload(headers_base64, body_base64, body_truncated, content_type);
    OutputLine::HttpEvent(HttpEventLine {
        timestamp,
        pid,
        event: "decrypted_http_request".into(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        status_line: None,
        version: version.to_owned(),
        headers_base64: headers_base64.map(str::to_owned),
        headers: payload.headers,
        headers_truncated,
        status_code: None,
        host: host.map(str::to_owned),
        content_type: content_type.map(str::to_owned),
        content_length,
        decrypted: true,
        content_encoding: content_encoding.map(str::to_owned),
        decoded,
        body_base64: body_base64.map(str::to_owned),
        body_format: payload.body_format,
        body_text: payload.body_text,
        body_json: payload.body_json,
        sse_events: payload.sse_events,
        body_truncated,
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "decrypted HTTP schema projection keeps source fields explicit"
)]
pub(super) fn decrypted_http_response_line(
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
    headers_base64: Option<&str>,
    headers_truncated: bool,
    content_encoding: Option<&str>,
    decoded: bool,
    body_base64: Option<&str>,
    body_truncated: bool,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    let payload = project_http_payload(headers_base64, body_base64, body_truncated, content_type);
    OutputLine::HttpEvent(HttpEventLine {
        timestamp,
        pid,
        event: "decrypted_http_response".into(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        method: None,
        path: None,
        status_line: Some(status_line.to_owned()),
        version: version.to_owned(),
        headers_base64: headers_base64.map(str::to_owned),
        headers: payload.headers,
        headers_truncated,
        status_code: Some(status_code),
        host: host.map(str::to_owned),
        content_type: content_type.map(str::to_owned),
        content_length,
        decrypted: true,
        content_encoding: content_encoding.map(str::to_owned),
        decoded,
        body_base64: body_base64.map(str::to_owned),
        body_format: payload.body_format,
        body_text: payload.body_text,
        body_json: payload.body_json,
        sse_events: payload.sse_events,
        body_truncated,
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "tunnel data schema projection keeps source fields explicit"
)]
pub(super) fn tunnel_data_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    src: &str,
    dst: &str,
    direction: &str,
    encrypted: bool,
    headers_base64: Option<&str>,
    headers_truncated: bool,
    payload_base64: Option<&str>,
    payload_truncated: bool,
    bytes_seen: u64,
    bytes_captured: u64,
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

    OutputLine::TunnelDataEvent(TunnelDataEventLine {
        timestamp,
        pid,
        event: "tunnel_data".into(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        direction: direction.to_owned(),
        encrypted,
        headers_base64: headers_base64.map(str::to_owned),
        headers_truncated,
        payload_base64: payload_base64.map(str::to_owned),
        payload_truncated,
        bytes_seen,
        bytes_captured,
        process_name: name,
        ppid,
        command_line,
        tree_path,
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
    process_fields: ProcessFields,
) -> OutputLine {
    let ProcessFields {
        name,
        ppid,
        command_line,
        tree_path,
    } = process_fields;

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
        process_name: name,
        ppid,
        command_line,
        tree_path,
    })
}
