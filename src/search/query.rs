//! # `search::query`
//!
//! **Purpose**: Decodes payload search queries into one or more byte needles.
//! **Public API**: `SearchType`, `SearchError`
//! **Dependencies**: `base64`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 173 / 200

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Query encoding used when searching captured payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchType {
    /// Query text is UTF-8 and is searched as raw bytes.
    Utf8,
    /// Query text is hexadecimal; ASCII whitespace is ignored.
    Hex,
    /// Query text is base64.
    Base64,
    /// Query text is a signed 32-bit integer searched as big- and little-endian bytes.
    Int32,
    /// Query text is a signed 64-bit integer searched as big- and little-endian bytes.
    Int64,
    /// Query text is a 32-bit float searched as big- and little-endian bytes.
    Float32,
    /// Query text is a 64-bit float searched as big- and little-endian bytes.
    Float64,
}

/// Payload search decoding error.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    /// Query decoded to zero bytes.
    #[error("search query must not be empty")]
    EmptyQuery,
    /// Hex input contained an odd number of digits.
    #[error("hex search query must contain an even number of digits, got {digits}")]
    InvalidHexLength { digits: usize },
    /// Hex input contained a non-hex digit.
    #[error("invalid hex digit '{value}' at index {index}")]
    InvalidHexDigit { index: usize, value: char },
    /// Base64 decoding failed.
    #[error("invalid base64 search query: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    /// Int32 parsing failed.
    #[error("invalid int32 search query '{value}': {source}")]
    InvalidInt32 {
        value: String,
        source: std::num::ParseIntError,
    },
    /// Int64 parsing failed.
    #[error("invalid int64 search query '{value}': {source}")]
    InvalidInt64 {
        value: String,
        source: std::num::ParseIntError,
    },
    /// Float32 parsing failed.
    #[error("invalid float32 search query '{value}': {source}")]
    InvalidFloat32 {
        value: String,
        source: std::num::ParseFloatError,
    },
    /// Float64 parsing failed.
    #[error("invalid float64 search query '{value}': {source}")]
    InvalidFloat64 {
        value: String,
        source: std::num::ParseFloatError,
    },
}

pub(super) fn decode_queries(
    query: &str,
    search_type: SearchType,
) -> Result<Vec<Vec<u8>>, SearchError> {
    match search_type {
        SearchType::Utf8 => Ok(vec![query.as_bytes().to_vec()]),
        SearchType::Hex => Ok(vec![decode_hex(query)?]),
        SearchType::Base64 => Ok(vec![STANDARD.decode(query)?]),
        SearchType::Int32 => int32_needles(query),
        SearchType::Int64 => int64_needles(query),
        SearchType::Float32 => float32_needles(query),
        SearchType::Float64 => float64_needles(query),
    }
}

fn int32_needles(query: &str) -> Result<Vec<Vec<u8>>, SearchError> {
    let value = query
        .trim()
        .parse::<i32>()
        .map_err(|source| SearchError::InvalidInt32 {
            value: query.to_string(),
            source,
        })?;
    Ok(endian_needles(value.to_be_bytes(), value.to_le_bytes()))
}

fn int64_needles(query: &str) -> Result<Vec<Vec<u8>>, SearchError> {
    let value = query
        .trim()
        .parse::<i64>()
        .map_err(|source| SearchError::InvalidInt64 {
            value: query.to_string(),
            source,
        })?;
    Ok(endian_needles(value.to_be_bytes(), value.to_le_bytes()))
}

fn float32_needles(query: &str) -> Result<Vec<Vec<u8>>, SearchError> {
    let value = query
        .trim()
        .parse::<f32>()
        .map_err(|source| SearchError::InvalidFloat32 {
            value: query.to_string(),
            source,
        })?;
    Ok(endian_needles(value.to_be_bytes(), value.to_le_bytes()))
}

fn float64_needles(query: &str) -> Result<Vec<Vec<u8>>, SearchError> {
    let value = query
        .trim()
        .parse::<f64>()
        .map_err(|source| SearchError::InvalidFloat64 {
            value: query.to_string(),
            source,
        })?;
    Ok(endian_needles(value.to_be_bytes(), value.to_le_bytes()))
}

fn endian_needles<const N: usize>(be: [u8; N], le: [u8; N]) -> Vec<Vec<u8>> {
    let be = be.to_vec();
    let le = le.to_vec();
    if be == le {
        vec![be]
    } else {
        vec![be, le]
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, SearchError> {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.len() & 1 == 1 {
        return Err(SearchError::InvalidHexLength {
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

fn hex_digit(byte: u8, index: usize) -> Result<u8, SearchError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SearchError::InvalidHexDigit {
            index,
            value: char::from(byte),
        }),
    }
}
