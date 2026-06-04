//! # `output`
//!
//! **Purpose**: Event serialization to NDJSON stdout — the stable agent API surface.
//! **Public API**: `trait Emitter`, `mod schema`, `mod json`, `mod diagnostic`
//! **Dependencies**: `parser`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 24 / 60

pub mod diagnostic;
pub mod json;
pub mod schema;

use crate::{error::EtwardenError, parser::types::NetEvent};

/// Serializes `NetEvent` to an output sink.
pub trait Emitter: Send {
    /// Emits a single network event.
    ///
    /// # Arguments
    /// * `event` — The network event to emit.
    ///
    /// # Errors
    /// Returns [`EtwardenError::OutputWrite`] if the write fails.
    fn emit(&mut self, event: &NetEvent) -> std::result::Result<(), EtwardenError>;

    /// Flushes any buffered output.
    ///
    /// # Errors
    /// Returns [`EtwardenError::OutputWrite`] if the flush fails.
    fn flush(&mut self) -> std::result::Result<(), EtwardenError>;
}
