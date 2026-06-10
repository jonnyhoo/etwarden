//! # `search`
//!
//! **Purpose**: Payload search primitives and aggregation for captured traffic bytes.
//! **Public API**: `CapturedPayload`, `SearchAllResult`, `SearchType`, `SearchError`,
//!   `SearchResult`, `search_all`, `search_payload`
//! **Dependencies**: `search::{all, payload, query}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 19 / 80

mod all;
mod payload;
mod query;
#[cfg(test)]
mod tests;

pub use all::{search_all, CapturedPayload, SearchAllResult};
pub use payload::{search_payload, SearchResult};
pub use query::{SearchError, SearchType};
