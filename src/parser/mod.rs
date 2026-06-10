//! # `parser`
//!
//! **Purpose**: Parser facade for ETW provider parsers and shared parsed-event types.
//! **Public API**: `trait EventParser`, `struct ParserRegistry`, parser modules, `mod types`
//! **Dependencies**: (none — facade only)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 21 / 80

pub mod dns;
pub mod dns_codes;
pub mod dpi;
pub(crate) mod endpoint;
pub mod ndis;
pub mod protobuf;
mod registry;
pub mod tcp_state;
pub mod tcpip;
pub mod types;

pub use registry::{EventParser, ParserRegistry};
