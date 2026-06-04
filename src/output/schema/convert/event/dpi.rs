//! # `output::schema::convert::event::dpi`
//!
//! **Purpose**: Routes application-layer DPI events to HTTP/TLS schema projection.
//! **Public API**: module-private DPI event router
//! **Dependencies**: `output::schema::convert::dpi`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 90 / 140

use super::super::{
    dpi::{http_request_line, http_response_line, tls_hello_line},
    process::ProcessFields,
};
use crate::{output::schema::OutputLine, parser::types::NetEvent};

pub(super) fn line(event: &NetEvent, process_fields: ProcessFields) -> OutputLine {
    match *event {
        NetEvent::HttpRequest {
            timestamp,
            pid,
            ref src,
            ref dst,
            ref method,
            ref path,
            ref host,
            ref version,
            ref content_type,
            content_length,
        } => http_request_line(
            timestamp,
            pid,
            src,
            dst,
            method,
            path,
            version,
            host.as_deref(),
            content_type.as_deref(),
            content_length,
            process_fields,
        ),
        NetEvent::HttpResponse {
            timestamp,
            pid,
            ref src,
            ref dst,
            ref status_line,
            ref host,
            ref version,
            status_code,
            ref content_type,
            content_length,
        } => http_response_line(
            timestamp,
            pid,
            src,
            dst,
            status_line,
            version,
            status_code,
            host.as_deref(),
            content_type.as_deref(),
            content_length,
            process_fields,
        ),
        NetEvent::TlsHello {
            timestamp,
            pid,
            ref src,
            ref dst,
            ref sni,
            ref version,
            ja3: ref classic_text,
            ja3_hash: ref classic_hash,
            ja3n: ref normalized_text,
            ja3n_hash: ref normalized_hash,
            ja4: ref sorted_fingerprint,
            ja4o: ref original_fingerprint,
            ja4r: ref sorted_raw,
            ja4ro: ref original_raw,
            ref alpn,
            cipher_count,
            extension_count,
        } => tls_hello_line(
            timestamp,
            pid,
            src,
            dst,
            sni.as_deref(),
            version.as_deref(),
            classic_text,
            classic_hash,
            normalized_text,
            normalized_hash,
            sorted_fingerprint,
            original_fingerprint,
            sorted_raw,
            original_raw,
            alpn,
            cipher_count,
            extension_count,
            process_fields,
        ),
        _ => super::unsupported_event_line(),
    }
}
