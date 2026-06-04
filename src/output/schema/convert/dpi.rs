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
    host: Option<&str>,
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
        host: host.map(str::to_owned),
        process_name,
    })
}

pub(super) fn http_response_line(
    timestamp: DateTime<Utc>,
    pid: u32,
    src: &str,
    dst: &str,
    status_line: &str,
    host: Option<&str>,
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
        host: host.map(str::to_owned),
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
        process_name,
    })
}
