//! # `mitm::body::tests`
//!
//! **Purpose**: Unit tests for MITM body capture and decoding.
//! **Public API**: test module only
//! **Dependencies**: `mitm::body`, `flate2`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 72 / 120

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
fn invalid_gzip_body_falls_back_to_raw_capture() {
    let captured = capture_body(Some("gzip"), None, b"not gzip", 64).expect("capture");

    assert_eq!(captured.body_base64.as_deref(), Some("bm90IGd6aXA="));
    assert_eq!(captured.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(captured.content_length, Some(8));
    assert!(!captured.decoded);
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

#[test]
fn raw_bytes_capture_is_bounded() {
    let captured = capture_bytes_base64(b"abcdef", 3);

    assert_eq!(captured.base64.as_deref(), Some("YWJj"));
    assert!(captured.truncated);
    assert_eq!(captured.captured_len, 3);
}
