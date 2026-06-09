//! # `mitm::transparent::tcp`
//!
//! **Purpose**: Raw TCP passthrough for transparent non-HTTP traffic.
//! **Public API**: module-private tunnel helper
//! **Dependencies**: `mitm`, `tokio`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 137 / 160

use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::TransparentUpstream;
use crate::{
    error::{EtwardenError, Result},
    mitm::{body::capture_bytes_base64, ProxyState},
    output::diagnostic,
    parser::types::NetEvent,
};

const COPY_BUF_SIZE: usize = 16 * 1024;

struct DirectionCapture {
    bytes_seen: u64,
    bytes: Vec<u8>,
    truncated: bool,
}

impl DirectionCapture {
    fn new(limit: usize) -> Self {
        Self {
            bytes_seen: 0,
            bytes: Vec::with_capacity(limit.min(COPY_BUF_SIZE)),
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8], limit: usize) {
        self.bytes_seen = self
            .bytes_seen
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let remaining = limit.saturating_sub(self.bytes.len());
        if remaining == 0 {
            self.truncated = true;
            return;
        }
        let take = remaining.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..take]);
        self.truncated |= take < chunk.len();
    }
}

pub(super) async fn tunnel_tcp(
    client: TcpStream,
    remote_addr: SocketAddr,
    state: Arc<ProxyState>,
    upstream: TransparentUpstream,
) -> Result<()> {
    let target = SocketAddr::V4(SocketAddrV4::new(upstream.dest.ip, upstream.dest.port));
    let server = TcpStream::connect(target)
        .await
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent TCP connect failed: {e}")))?;
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    let capture_limit = state
        .body_limit
        .saturating_mul(2)
        .min(state.max_body_bytes)
        .max(state.body_limit);
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();
    let (request, response) = tokio::try_join!(
        copy_with_capture(client_read, server_write, capture_limit),
        copy_with_capture(server_read, client_write, capture_limit),
    )?;

    let local = format!("{}:{}", upstream.dest.local_ip, remote_addr.port());
    let target_text = target.to_string();
    let encrypted = upstream.dest.port == 443;
    let request_bytes_seen = request.bytes_seen;
    let response_bytes_seen = response.bytes_seen;
    emit_tunnel_data(
        &state,
        &upstream,
        &local,
        &target_text,
        "request",
        encrypted,
        request,
    );
    emit_tunnel_data(
        &state,
        &upstream,
        &target_text,
        &local,
        "response",
        encrypted,
        response,
    );

    diagnostic::info(format_args!(
        "transparent TCP tunnel closed pid={} target={} up={} down={}",
        upstream.dest.pid, target, request_bytes_seen, response_bytes_seen,
    ));
    Ok(())
}

async fn copy_with_capture<R, W>(
    mut reader: R,
    mut writer: W,
    limit: usize,
) -> Result<DirectionCapture>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut capture = DirectionCapture::new(limit);
    let mut buf = [0u8; COPY_BUF_SIZE];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| EtwardenError::MitmProxy(format!("transparent TCP read failed: {e}")))?;
        if n == 0 {
            break;
        }
        capture.push(&buf[..n], limit);
        writer
            .write_all(&buf[..n])
            .await
            .map_err(|e| EtwardenError::MitmProxy(format!("transparent TCP write failed: {e}")))?;
    }
    writer
        .shutdown()
        .await
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent TCP shutdown failed: {e}")))?;
    Ok(capture)
}

fn emit_tunnel_data(
    state: &ProxyState,
    upstream: &TransparentUpstream,
    src: &str,
    dst: &str,
    direction: &str,
    forced_encrypted: bool,
    capture: DirectionCapture,
) {
    if capture.bytes_seen == 0 {
        return;
    }
    let parsed = parse_captured_data(&capture.bytes, state.body_limit, capture.truncated);
    let bytes_captured = parsed
        .headers_captured
        .saturating_add(parsed.payload_captured);
    let _ = state.registry.push_event(NetEvent::TunnelData {
        timestamp: chrono::Utc::now(),
        pid: upstream.dest.pid,
        src: src.to_owned(),
        dst: dst.to_owned(),
        direction: direction.to_owned(),
        encrypted: forced_encrypted || looks_tls(&capture.bytes),
        headers_base64: parsed.headers_base64,
        headers_truncated: parsed.headers_truncated,
        payload_base64: parsed.payload_base64,
        payload_truncated: parsed.payload_truncated,
        bytes_seen: capture.bytes_seen,
        bytes_captured: u64::try_from(bytes_captured).unwrap_or(u64::MAX),
    });
}

struct ParsedCapture {
    headers_base64: Option<String>,
    headers_truncated: bool,
    headers_captured: usize,
    payload_base64: Option<String>,
    payload_truncated: bool,
    payload_captured: usize,
}

fn parse_captured_data(bytes: &[u8], limit: usize, stream_truncated: bool) -> ParsedCapture {
    if let Some((header_end, payload_start)) = http_header_range(bytes) {
        let headers = capture_bytes_base64(&bytes[..header_end], limit);
        let payload = capture_bytes_base64(&bytes[payload_start..], limit);
        return ParsedCapture {
            headers_base64: headers.base64,
            headers_truncated: headers.truncated,
            headers_captured: headers.captured_len,
            payload_base64: payload.base64,
            payload_truncated: payload.truncated || stream_truncated,
            payload_captured: payload.captured_len,
        };
    }

    let payload = capture_bytes_base64(bytes, limit);
    ParsedCapture {
        headers_base64: None,
        headers_truncated: false,
        headers_captured: 0,
        payload_base64: payload.base64,
        payload_truncated: payload.truncated || stream_truncated,
        payload_captured: payload.captured_len,
    }
}

fn http_header_range(bytes: &[u8]) -> Option<(usize, usize)> {
    if !looks_http(bytes) {
        return None;
    }
    if let Some(pos) = bytes.windows(4).position(|win| win == b"\r\n\r\n") {
        return Some((pos + 4, pos + 4));
    }
    bytes
        .windows(2)
        .position(|win| win == b"\n\n")
        .map(|pos| (pos + 2, pos + 2))
}

fn looks_http(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
        b"HTTP/",
    ];
    PREFIXES.iter().any(|prefix| bytes.starts_with(prefix))
}

fn looks_tls(bytes: &[u8]) -> bool {
    bytes.len() >= 5
        && (0x14..=0x17).contains(&bytes[0])
        && bytes[1] == 0x03
        && (0x01..=0x04).contains(&bytes[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_capture_splits_headers_and_payload() {
        let parsed = parse_captured_data(b"POST / HTTP/1.1\r\nHost: x\r\n\r\nbody", 64, false);

        assert!(parsed.headers_base64.is_some());
        assert!(parsed.payload_base64.is_some());
        assert!(!parsed.payload_truncated);
    }

    #[test]
    fn encrypted_capture_uses_payload_field() {
        let parsed = parse_captured_data(&[0x16, 0x03, 0x03, 0, 1, 0], 64, false);

        assert!(parsed.headers_base64.is_none());
        assert!(parsed.payload_base64.is_some());
    }

    #[test]
    fn tls_application_data_looks_encrypted() {
        assert!(looks_tls(&[0x17, 0x03, 0x03, 0, 1, 0]));
    }
}
