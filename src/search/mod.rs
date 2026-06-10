//! # `search`
//!
//! **Purpose**: Payload search primitives and aggregation for captured traffic bytes.
//! **Public API**: `CapturedPayload`, `ProtobufSearchConfig`, `ProtobufSearchError`,
//!   `SearchAllResult`, `SearchType`, `SearchError`, `SearchResult`, `search_all`,
//!   `search_payload`, `search_protobuf_all`, `search_protobuf_payload`
//! **Dependencies**: `search::{all, payload, protobuf, query}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 24 / 80

mod all;
mod payload;
mod protobuf;
mod query;
#[cfg(test)]
mod tests;

pub use all::{search_all, CapturedPayload, SearchAllResult};
pub use payload::{search_payload, SearchResult};
pub use protobuf::{
    search_protobuf_all, search_protobuf_payload, ProtobufSearchConfig, ProtobufSearchError,
};
pub use query::{SearchError, SearchType};
