//! # `search::payload`
//!
//! **Purpose**: Finds byte-pattern matches inside one captured payload.
//! **Public API**: `SearchResult`, `search_payload`
//! **Dependencies**: `search::query`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 116 / 200

use super::query::{decode_queries, SearchError, SearchType};

const CONTEXT_BYTES: usize = 64;

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
    search_payload_with_needles(payload, &needles, search_type, case_sensitive)
}

pub(super) fn search_payload_with_needles(
    payload: &[u8],
    needles: &[Vec<u8>],
    search_type: SearchType,
    case_sensitive: bool,
) -> Result<Vec<SearchResult>, SearchError> {
    if needles.iter().any(Vec::is_empty) {
        return Err(SearchError::EmptyQuery);
    }
    let mut results = Vec::new();
    for needle in needles {
        let matches = if case_sensitive || search_type != SearchType::Utf8 {
            find_bytes(payload, needle)
        } else {
            find_ascii_case_insensitive(payload, needle)
        };
        for offset in matches {
            push_unique_result(&mut results, payload, offset, needle.len());
        }
    }
    results.sort_by_key(|hit| hit.offset);
    Ok(results)
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

fn ascii_lowercase(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}
