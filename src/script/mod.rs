//! # `script`
//!
//! **Purpose**: Sandboxed Lua scripting hooks for traffic mutation.
//! **Public API**: `HttpScriptDecision`, `HttpScriptRequest`, `ScriptEngine`, `ScriptError`
//! **Dependencies**: `script::{engine, types}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 16 / 80

mod engine;
#[cfg(test)]
mod tests;
mod types;

pub use engine::ScriptEngine;
pub use types::{HttpScriptDecision, HttpScriptRequest, ScriptError};
