//! # `rules::config::value`
//!
//! **Purpose**: Rule config value encoding and byte decoding.
//! **Public API**: `RuleValueEncoding`, `RuleConfigError`
//! **Dependencies**: `base64`, `serde`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 85 / 120

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

/// Encoding for byte values in rule config.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub enum RuleValueEncoding {
    /// UTF-8 string bytes.
    #[serde(rename = "UTF8", alias = "utf8", alias = "Utf8")]
    #[default]
    Utf8,
    /// Hexadecimal bytes. ASCII whitespace is ignored.
    #[serde(rename = "HEX", alias = "hex", alias = "Hex")]
    Hex,
    /// Base64 bytes.
    #[serde(rename = "BASE64", alias = "Base64", alias = "base64")]
    Base64,
}

/// Rules config decoding error.
#[derive(Debug, thiserror::Error)]
pub enum RuleConfigError {
    /// Hex input contained an odd number of digits.
    #[error("hex value must contain an even number of digits, got {digits}")]
    InvalidHexLength { digits: usize },
    /// Hex input contained a non-hex digit.
    #[error("invalid hex digit '{value}' at index {index}")]
    InvalidHexDigit { index: usize, value: char },
    /// Base64 decoding failed.
    #[error("invalid base64 value: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

pub(super) fn decode_value(
    value: &str,
    encoding: RuleValueEncoding,
) -> Result<Vec<u8>, RuleConfigError> {
    match encoding {
        RuleValueEncoding::Utf8 => Ok(value.as_bytes().to_vec()),
        RuleValueEncoding::Hex => decode_hex(value),
        RuleValueEncoding::Base64 => Ok(STANDARD.decode(value)?),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RuleConfigError> {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.len() & 1 == 1 {
        return Err(RuleConfigError::InvalidHexLength {
            digits: digits.len(),
        });
    }

    digits
        .chunks_exact(2)
        .enumerate()
        .map(|(pair_index, pair)| {
            let high = hex_digit(pair[0], pair_index * 2)?;
            let low = hex_digit(pair[1], pair_index * 2 + 1)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8, index: usize) -> Result<u8, RuleConfigError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RuleConfigError::InvalidHexDigit {
            index,
            value: char::from(byte),
        }),
    }
}
