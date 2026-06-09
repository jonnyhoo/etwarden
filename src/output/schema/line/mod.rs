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
mod process;

pub use event::{
    DnsEventLine, EventLine, HttpEventLine, HttpHeaderLine, HttpSseEventLine, RuleHitEventLine,
    TlsEventLine, TunnelDataEventLine,
};
pub use meta::{ErrorLine, OutputLine, SummaryLine};
pub use process::{ProcessKillLine, ProcessLine, SpawnTargetLine};
