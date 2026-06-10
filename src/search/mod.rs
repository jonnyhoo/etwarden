//! # `search`
//!
//! **Purpose**: Payload search primitives for captured traffic bytes.
//! **Public API**: `SearchType`, `SearchError`, `SearchResult`, `search_payload`
//! **Dependencies**: `search::{payload, query}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 16 / 80

mod payload;
mod query;
#[cfg(test)]
mod tests;

pub use payload::{search_payload, SearchResult};
pub use query::{SearchError, SearchType};
