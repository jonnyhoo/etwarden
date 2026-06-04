//! # `mitm::body`
//!
//! **Purpose**: Decompresses and bounds captured MITM HTTP bodies before NDJSON emission.
//! **Public API**: `CapturedBody`, `capture_body`
//! **Dependencies**: `base64`, `brotli`, `flate2`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 160

use std::io::Read;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::{DeflateDecoder, GzDecoder};

use crate::error::{EtwardenError, Result};

/// Bounded, NDJSON-safe body capture metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedBody {
    pub content_encoding: Option<String>,
    pub decoded: bool,
    pub content_length: Option<u64>,
    pub body_base64: Option<String>,
    pub body_truncated: bool,
}

/// Captures a HTTP body, decoding common content encodings and base64-wrapping bytes.
///
/// `limit` caps the emitted body bytes. It does not hide truncation.
pub fn capture_body(
    content_encoding: Option<&str>,
    header_content_length: Option<u64>,
    body: &[u8],
    limit: usize,
) -> Result<CapturedBody> {
    if body.is_empty() {
        return Ok(CapturedBody {
            content_encoding: content_encoding.map(str::to_owned),
            decoded: false,
            content_length: header_content_length,
            body_base64: None,
            body_truncated: false,
        });
    }

    let decoded = decode_body(content_encoding, body)?;
    let full_len = decoded.bytes.len();
    let body_truncated = full_len > limit;
    let captured = if body_truncated {
        &decoded.bytes[..limit]
    } else {
        decoded.bytes.as_slice()
    };

    Ok(CapturedBody {
        content_encoding: if decoded.decoded {
            None
        } else {
            content_encoding.map(str::to_owned)
        },
        decoded: decoded.decoded,
        content_length: u64::try_from(full_len).ok(),
        body_base64: Some(STANDARD.encode(captured)),
        body_truncated,
    })
}

struct DecodedBody {
    bytes: Vec<u8>,
    decoded: bool,
}

fn decode_body(content_encoding: Option<&str>, body: &[u8]) -> Result<DecodedBody> {
    let Some(encoding) = content_encoding.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(DecodedBody {
            bytes: body.to_vec(),
            decoded: false,
        });
    };

    let bytes = match encoding.to_ascii_lowercase().as_str() {
        "gzip" => read_all(GzDecoder::new(body), "gzip")?,
        "deflate" => read_all(DeflateDecoder::new(body), "deflate")?,
        "br" => read_all(brotli::Decompressor::new(body, 4096), "br")?,
        _ => {
            return Ok(DecodedBody {
                bytes: body.to_vec(),
                decoded: false,
            });
        }
    };

    Ok(DecodedBody {
        bytes,
        decoded: true,
    })
}

fn read_all(mut reader: impl Read, encoding: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to decode {encoding} body: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::GzEncoder, Compression};

    use super::*;

    #[test]
    fn raw_body_is_base64_encoded() {
        let captured = capture_body(None, Some(5), b"hello", 32).expect("capture");
        assert_eq!(captured.body_base64.as_deref(), Some("aGVsbG8="));
        assert_eq!(captured.content_length, Some(5));
        assert!(!captured.decoded);
    }

    #[test]
    fn gzip_body_is_decoded_and_encoding_removed() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"hello gzip").expect("write gzip");
        let zipped = encoder.finish().expect("finish gzip");

        let captured = capture_body(Some("gzip"), None, &zipped, 64).expect("capture");

        assert_eq!(captured.body_base64.as_deref(), Some("aGVsbG8gZ3ppcA=="));
        assert_eq!(captured.content_encoding, None);
        assert!(captured.decoded);
    }

    #[test]
    fn body_limit_sets_truncation_flag() {
        let captured = capture_body(None, None, b"abcdef", 3).expect("capture");

        assert_eq!(captured.body_base64.as_deref(), Some("YWJj"));
        assert_eq!(captured.content_length, Some(6));
        assert!(captured.body_truncated);
    }

    #[test]
    fn unknown_encoding_keeps_original_encoding() {
        let captured = capture_body(Some("zstd"), None, b"abc", 8).expect("capture");

        assert_eq!(captured.content_encoding.as_deref(), Some("zstd"));
        assert!(!captured.decoded);
    }
}
