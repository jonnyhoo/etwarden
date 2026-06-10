//! # `search::payload`
//!
//! **Purpose**: Finds byte-pattern matches inside one captured payload.
//! **Public API**: `SearchType`, `SearchError`, `SearchResult`, `search_payload`
//! **Dependencies**: `base64`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 199 / 200

use base64::{engine::general_purpose::STANDARD, Engine as _};

const CONTEXT_BYTES: usize = 64;

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
}

/// One match inside a captured payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// Byte offset of the match within the payload.
    pub offset: usize,
    /// Matched byte length.
    pub length: usize,
    /// Context bytes around the match, up to 64 bytes on each side.
    pub context: Vec<u8>,
}

/// Searches one captured payload for all matching byte ranges.
///
/// # Arguments
/// * `payload` — Captured request/response/tunnel bytes.
/// * `query` — Search query encoded according to `search_type`.
/// * `search_type` — Query decoding mode.
/// * `case_sensitive` — Whether ASCII text search is case-sensitive.
///
/// # Returns
/// All matches, including overlapping matches, in payload order.
///
/// # Errors
/// Returns [`SearchError`] when the query cannot be decoded or decodes to empty bytes.
pub fn search_payload(
    payload: &[u8],
    query: &str,
    search_type: SearchType,
    case_sensitive: bool,
) -> Result<Vec<SearchResult>, SearchError> {
    let needles = decode_queries(query, search_type)?;
    if needles.iter().any(Vec::is_empty) {
        return Err(SearchError::EmptyQuery);
    }
    let mut results = Vec::new();
    for needle in needles {
        let matches = if case_sensitive || search_type != SearchType::Utf8 {
            find_bytes(payload, &needle)
        } else {
            find_ascii_case_insensitive(payload, &needle)
        };
        for offset in matches {
            push_unique_result(&mut results, payload, offset, needle.len());
        }
    }
    results.sort_by_key(|hit| hit.offset);
    Ok(results)
}

fn decode_queries(query: &str, search_type: SearchType) -> Result<Vec<Vec<u8>>, SearchError> {
    match search_type {
        SearchType::Utf8 => Ok(vec![query.as_bytes().to_vec()]),
        SearchType::Hex => Ok(vec![decode_hex(query)?]),
        SearchType::Base64 => Ok(vec![STANDARD.decode(query)?]),
        SearchType::Int32 => int32_needles(query),
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
    let be = value.to_be_bytes().to_vec();
    let le = value.to_le_bytes().to_vec();
    Ok(if be == le { vec![be] } else { vec![be, le] })
}

fn push_unique_result(
    results: &mut Vec<SearchResult>,
    payload: &[u8],
    offset: usize,
    length: usize,
) {
    if results
        .iter()
        .any(|hit| hit.offset == offset && hit.length == length)
    {
        return;
    }
    results.push(SearchResult {
        offset,
        length,
        context: context_bytes(payload, offset, length),
    });
}

fn find_bytes(payload: &[u8], needle: &[u8]) -> Vec<usize> {
    payload
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle).then_some(offset))
        .collect()
}

fn find_ascii_case_insensitive(payload: &[u8], needle: &[u8]) -> Vec<usize> {
    let needle = ascii_lowercase(needle);
    payload
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (ascii_lowercase(window) == needle).then_some(offset))
        .collect()
}

fn context_bytes(payload: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let start = offset.saturating_sub(CONTEXT_BYTES);
    let end = offset.saturating_add(length).saturating_add(CONTEXT_BYTES);
    payload[start..end.min(payload.len())].to_vec()
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

fn ascii_lowercase(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}
