//! # `output::schema::line`
//!
//! **Purpose**: Stable agent-contract line types re-exported by `output::schema`.
//! **Public API**: module-private facade for line type groups
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 18 / 60

mod event;
mod meta;

pub use event::{DnsEventLine, EventLine, HttpEventLine, RuleHitEventLine, TlsEventLine};
pub use meta::{ErrorLine, OutputLine, SummaryLine};
