//! # `search`
//!
//! **Purpose**: Payload search primitives and aggregation for captured traffic bytes.
//! **Public API**: `CapturedPayload`, `CapturedTraffic`, `ProtobufSearchConfig`,
//!   `ProtobufSearchError`, `SearchAllResult`, `SearchType`, `SearchError`, `SearchResult`,
//!   `TrafficPayloadKind`, `TrafficSearchError`, `TrafficSearchResult`, `search_all`,
//!   `search_payload`, `search_protobuf_all`, `search_protobuf_payload`, `search_traffic`
//! **Dependencies**: `search::{all, payload, protobuf, query, traffic}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 29 / 80

mod all;
mod payload;
mod protobuf;
mod query;
#[cfg(test)]
mod tests;
mod traffic;

pub use all::{search_all, CapturedPayload, SearchAllResult};
pub use payload::{search_payload, SearchResult};
pub use protobuf::{
    search_protobuf_all, search_protobuf_payload, ProtobufSearchConfig, ProtobufSearchError,
};
pub use query::{SearchError, SearchType};
pub use traffic::{
    search_traffic, CapturedTraffic, TrafficPayloadKind, TrafficSearchError, TrafficSearchResult,
};
