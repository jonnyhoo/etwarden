//! # `search::traffic`
//!
//! **Purpose**: Searches byte payloads embedded in captured `NetEvent` traffic.
//! **Public API**: `CapturedTraffic`, `TrafficPayloadKind`, `TrafficSearchError`,
//!   `TrafficSearchResult`, `search_traffic`
//! **Dependencies**: `base64`, `parser::types`, `search::{payload, query}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 179 / 200

use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::{
    payload::{search_payload_with_needles, SearchResult},
    query::{decode_queries, SearchError, SearchType},
};
use crate::parser::types::NetEvent;

/// One captured traffic event searchable by record id.
#[derive(Debug, Clone, Copy)]
pub struct CapturedTraffic<'a> {
    /// Stable capture record id supplied by the caller.
    pub record_id: u64,
    /// Captured event whose embedded payload bytes should be searched.
    pub event: &'a NetEvent,
}

/// Searchable byte segment inside a captured traffic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPayloadKind {
    /// Decoded HTTP header bytes from a decrypted HTTP event.
    HttpHeaders,
    /// Decoded HTTP body bytes from a decrypted HTTP event.
    HttpBody,
    /// Decoded tunnel header bytes.
    TunnelHeaders,
    /// Decoded tunnel payload bytes.
    TunnelPayload,
}

/// One match inside a captured traffic segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSearchResult {
    /// Stable capture record id supplied by the caller.
    pub record_id: u64,
    /// Segment where the match was found.
    pub payload_kind: TrafficPayloadKind,
    /// Byte offset of the match within the decoded segment.
    pub offset: usize,
    /// Matched byte length.
    pub length: usize,
    /// Context bytes around the match, up to 64 bytes on each side.
    pub context: Vec<u8>,
}

/// Traffic search error.
#[derive(Debug, thiserror::Error)]
pub enum TrafficSearchError {
    /// Search query decoding failed.
    #[error(transparent)]
    Search(#[from] SearchError),
    /// Captured traffic payload was not valid base64.
    #[error("invalid base64 traffic payload for record {record_id} {payload_kind:?}: {source}")]
    PayloadDecode {
        /// Stable capture record id supplied by the caller.
        record_id: u64,
        /// Segment that failed to decode.
        payload_kind: TrafficPayloadKind,
        /// Base64 decode source error.
        source: base64::DecodeError,
    },
}

/// Searches captured traffic events for matching byte ranges.
///
/// # Arguments
/// * `traffic` — Captured traffic events with caller-supplied stable ids.
/// * `query` — Search query encoded according to `search_type`.
/// * `search_type` — Query decoding mode.
/// * `case_sensitive` — Whether ASCII text search is case-sensitive.
///
/// # Returns
/// All matches, preserving input traffic order and per-segment offset order.
///
/// # Errors
/// Returns [`TrafficSearchError`] when query or captured base64 payload decoding fails.
pub fn search_traffic(
    traffic: &[CapturedTraffic<'_>],
    query: &str,
    search_type: SearchType,
    case_sensitive: bool,
) -> Result<Vec<TrafficSearchResult>, TrafficSearchError> {
    let needles = decode_queries(query, search_type)?;
    if needles.iter().any(Vec::is_empty) {
        return Err(SearchError::EmptyQuery.into());
    }

    let mut results = Vec::new();
    for item in traffic {
        for segment in payload_segments(item.event) {
            let payload = decode_payload(item.record_id, segment.kind, segment.value)?;
            let hits =
                search_payload_with_needles(&payload, &needles, search_type, case_sensitive)?;
            results.extend(
                hits.into_iter()
                    .map(|hit| hit.with_traffic(item.record_id, segment.kind)),
            );
        }
    }
    Ok(results)
}

#[derive(Debug, Clone, Copy)]
struct PayloadSegment<'a> {
    kind: TrafficPayloadKind,
    value: &'a str,
}

fn payload_segments(event: &NetEvent) -> Vec<PayloadSegment<'_>> {
    match event {
        NetEvent::DecryptedHttpRequest {
            headers_base64,
            body_base64,
            ..
        }
        | NetEvent::DecryptedHttpResponse {
            headers_base64,
            body_base64,
            ..
        } => optional_segments([
            (TrafficPayloadKind::HttpHeaders, headers_base64.as_deref()),
            (TrafficPayloadKind::HttpBody, body_base64.as_deref()),
        ]),
        NetEvent::TunnelData {
            headers_base64,
            payload_base64,
            ..
        } => optional_segments([
            (TrafficPayloadKind::TunnelHeaders, headers_base64.as_deref()),
            (TrafficPayloadKind::TunnelPayload, payload_base64.as_deref()),
        ]),
        _ => Vec::new(),
    }
}

fn optional_segments<const N: usize>(
    items: [(TrafficPayloadKind, Option<&str>); N],
) -> Vec<PayloadSegment<'_>> {
    items
        .into_iter()
        .filter_map(|(kind, value)| value.map(|value| PayloadSegment { kind, value }))
        .collect()
}

fn decode_payload(
    record_id: u64,
    payload_kind: TrafficPayloadKind,
    value: &str,
) -> Result<Vec<u8>, TrafficSearchError> {
    STANDARD
        .decode(value)
        .map_err(|source| TrafficSearchError::PayloadDecode {
            record_id,
            payload_kind,
            source,
        })
}

impl SearchResult {
    fn with_traffic(self, record_id: u64, payload_kind: TrafficPayloadKind) -> TrafficSearchResult {
        TrafficSearchResult {
            record_id,
            payload_kind,
            offset: self.offset,
            length: self.length,
            context: self.context,
        }
    }
}
