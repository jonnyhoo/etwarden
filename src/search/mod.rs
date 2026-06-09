//! # `search`
//!
//! **Purpose**: Payload search primitives for captured traffic bytes.
//! **Public API**: `SearchType`, `SearchError`, `SearchResult`, `search_payload`
//! **Dependencies**: `search::payload`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 16 / 80

mod payload;
#[cfg(test)]
mod tests;

pub use payload::{search_payload, SearchError, SearchResult, SearchType};
