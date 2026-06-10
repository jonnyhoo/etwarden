//! # `search::protobuf`
//!
//! **Purpose**: Searches decoded Protobuf JSON payloads.
//! **Public API**: `ProtobufSearchConfig`, `ProtobufSearchError`, `search_protobuf_all`,
//!   `search_protobuf_payload`
//! **Dependencies**: `parser::protobuf`, `search::{all, payload, query}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 111 / 200

use super::{
    all::{CapturedPayload, SearchAllResult},
    payload::{search_payload_with_needles, SearchResult},
    query::{decode_queries, SearchError, SearchType},
};
use crate::parser::protobuf::{protobuf_to_json, ProtobufError, ProtobufSchema};

/// Protobuf decoding parameters for JSON-backed search.
#[derive(Debug, Clone, Copy)]
pub struct ProtobufSearchConfig<'a> {
    /// Imported Protobuf schema.
    pub schema: &'a ProtobufSchema,
    /// Number of leading bytes to skip before decoding the payload.
    pub skip: usize,
    /// Fully qualified Protobuf message type name.
    pub message_type: &'a str,
}

/// Protobuf search error.
#[derive(Debug, thiserror::Error)]
pub enum ProtobufSearchError {
    /// Protobuf schema lookup, binary decode, or JSON serialization failed.
    #[error(transparent)]
    Protobuf(#[from] ProtobufError),
    /// Search query decoding failed.
    #[error(transparent)]
    Search(#[from] SearchError),
}

/// Searches one Protobuf payload after decoding it to JSON.
///
/// # Arguments
/// * `payload` — Binary Protobuf payload bytes.
/// * `config` — Protobuf schema, skip, and message type.
/// * `query` — Search query encoded according to `search_type`.
/// * `search_type` — Query decoding mode applied to decoded JSON bytes.
/// * `case_sensitive` — Whether ASCII text search is case-sensitive.
///
/// # Returns
/// Matches inside the decoded JSON byte representation.
///
/// # Errors
/// Returns [`ProtobufSearchError`] when Protobuf decoding or query decoding fails.
pub fn search_protobuf_payload(
    payload: &[u8],
    config: ProtobufSearchConfig<'_>,
    query: &str,
    search_type: SearchType,
    case_sensitive: bool,
) -> Result<Vec<SearchResult>, ProtobufSearchError> {
    let needles = decode_queries(query, search_type)?;
    let json = protobuf_to_json(config.schema, payload, config.skip, config.message_type)?;
    Ok(search_payload_with_needles(
        json.as_bytes(),
        &needles,
        search_type,
        case_sensitive,
    )?)
}

/// Searches all Protobuf payloads after decoding each payload to JSON.
///
/// # Arguments
/// * `payloads` — Captured binary Protobuf payloads with ids.
/// * `config` — Protobuf schema, skip, and message type.
/// * `query` — Search query encoded according to `search_type`.
/// * `search_type` — Query decoding mode applied to decoded JSON bytes.
/// * `case_sensitive` — Whether ASCII text search is case-sensitive.
///
/// # Returns
/// Matches inside decoded JSON byte representations, preserving input payload order.
///
/// # Errors
/// Returns [`ProtobufSearchError`] when Protobuf decoding or query decoding fails.
pub fn search_protobuf_all(
    payloads: &[CapturedPayload<'_>],
    config: ProtobufSearchConfig<'_>,
    query: &str,
    search_type: SearchType,
    case_sensitive: bool,
) -> Result<Vec<SearchAllResult>, ProtobufSearchError> {
    let needles = decode_queries(query, search_type)?;
    let mut results = Vec::new();
    for payload in payloads {
        let json = protobuf_to_json(
            config.schema,
            payload.payload,
            config.skip,
            config.message_type,
        )?;
        let hits =
            search_payload_with_needles(json.as_bytes(), &needles, search_type, case_sensitive)?;
        results.extend(hits.into_iter().map(|hit| SearchAllResult {
            request_id: payload.request_id,
            offset: hit.offset,
            length: hit.length,
            context: hit.context,
        }));
    }
    Ok(results)
}
