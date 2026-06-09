//! # `mitm::transparent::protocol`
//!
//! **Purpose**: Sniffs redirected TCP streams before choosing HTTP, TLS MITM, or raw TCP.
//! **Public API**: module-private protocol classifier
//! **Dependencies**: `tokio`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 127 / 130

use std::time::Duration;

use tokio::net::TcpStream;

use crate::error::{EtwardenError, Result};

const PEEK_BYTES: usize = 16;
const SNIFF_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum TransparentProtocol {
    Detect,
    Http,
    Tls,
    Tcp,
}

impl TransparentProtocol {
    pub(super) const fn uri_scheme(self) -> &'static str {
        match self {
            Self::Tls => "https",
            Self::Detect | Self::Http | Self::Tcp => "http",
        }
    }

    pub(super) const fn default_port(self) -> u16 {
        match self {
            Self::Tls => 443,
            Self::Detect | Self::Http | Self::Tcp => 80,
        }
    }
}

pub(super) async fn detect_stream_protocol(
    stream: &TcpStream,
    tls_mitm: bool,
) -> Result<TransparentProtocol> {
    let mut peek = [0u8; PEEK_BYTES];
    let n = match tokio::time::timeout(SNIFF_TIMEOUT, stream.peek(&mut peek)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return Err(EtwardenError::MitmProxy(format!(
                "transparent protocol sniff failed: {e}"
            )));
        }
        Err(_) => return Ok(TransparentProtocol::Tcp),
    };
    Ok(classify_peek(&peek[..n], tls_mitm))
}

fn classify_peek(bytes: &[u8], tls_mitm: bool) -> TransparentProtocol {
    if bytes.is_empty() {
        return TransparentProtocol::Tcp;
    }
    if looks_http(bytes) {
        return TransparentProtocol::Http;
    }
    if looks_tls(bytes) && tls_mitm {
        return TransparentProtocol::Tls;
    }
    TransparentProtocol::Tcp
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
    ];
    PREFIXES.iter().any(|prefix| bytes.starts_with(prefix))
}

fn looks_tls(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && (0x01..=0x04).contains(&bytes[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_request_is_http_without_port_hint() {
        assert_eq!(
            classify_peek(b"POST /v1/messages?beta=true HTTP/1.1\r\n", false),
            TransparentProtocol::Http
        );
    }

    #[test]
    fn tls_requires_explicit_mitm() {
        let client_hello = [0x16, 0x03, 0x03, 0x00, 0x2a];

        assert_eq!(
            classify_peek(&client_hello, false),
            TransparentProtocol::Tcp
        );
        assert_eq!(classify_peek(&client_hello, true), TransparentProtocol::Tls);
    }

    #[test]
    fn unknown_bytes_fall_back_to_tcp() {
        assert_eq!(
            classify_peek(b"\x01\x02\x03", true),
            TransparentProtocol::Tcp
        );
        assert_eq!(
            classify_peek(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", true),
            TransparentProtocol::Tcp
        );
    }
}
