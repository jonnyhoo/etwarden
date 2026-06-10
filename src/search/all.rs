//! # `search::all`
//!
//! **Purpose**: Aggregates payload searches across captured traffic records.
//! **Public API**: `CapturedPayload`, `SearchAllResult`, `search_all`
//! **Dependencies**: `search::{payload, query}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 83 / 200

use super::{
    payload::{search_payload_with_needles, SearchResult},
    query::{decode_queries, SearchError, SearchType},
};

/// One captured payload searchable by request id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedPayload<'a> {
    /// Stable request or capture record id.
    pub request_id: u64,
    /// Captured request/response/tunnel payload bytes.
    pub payload: &'a [u8],
}

/// One match inside a captured payload, attributed to a request id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchAllResult {
    /// Stable request or capture record id.
    pub request_id: u64,
    /// Byte offset of the match within the payload.
    pub offset: usize,
    /// Matched byte length.
    pub length: usize,
    /// Context bytes around the match, up to 64 bytes on each side.
    pub context: Vec<u8>,
}

/// Searches all captured payloads for matching byte ranges.
///
/// # Arguments
/// * `payloads` — Captured request/response/tunnel payloads with ids.
/// * `query` — Search query encoded according to `search_type`.
/// * `search_type` — Query decoding mode.
/// * `case_sensitive` — Whether ASCII text search is case-sensitive.
///
/// # Returns
/// All matches, preserving input payload order and per-payload offset order.
///
/// # Errors
/// Returns [`SearchError`] when the query cannot be decoded or decodes to empty bytes.
pub fn search_all(
    payloads: &[CapturedPayload<'_>],
    query: &str,
    search_type: SearchType,
    case_sensitive: bool,
) -> Result<Vec<SearchAllResult>, SearchError> {
    let needles = decode_queries(query, search_type)?;
    if needles.iter().any(Vec::is_empty) {
        return Err(SearchError::EmptyQuery);
    }

    let mut results = Vec::new();
    for payload in payloads {
        let matches =
            search_payload_with_needles(payload.payload, &needles, search_type, case_sensitive)?;
        results.extend(
            matches
                .into_iter()
                .map(|hit| hit.with_request(payload.request_id)),
        );
    }
    Ok(results)
}

impl SearchResult {
    fn with_request(self, request_id: u64) -> SearchAllResult {
        SearchAllResult {
            request_id,
            offset: self.offset,
            length: self.length,
            context: self.context,
        }
    }
}
