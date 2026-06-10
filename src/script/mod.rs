//! # `script`
//!
//! **Purpose**: Sandboxed Lua scripting hooks for traffic mutation.
//! **Public API**: `HttpScriptDecision`, `HttpScriptRequest`, `HttpScriptResponse`,
//!   `ScriptEngine`, `ScriptError`
//! **Dependencies**: `script::{engine, http, types}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 18 / 80

mod engine;
mod http;
#[cfg(test)]
mod tests;
mod types;

pub use engine::ScriptEngine;
pub use types::{HttpScriptDecision, HttpScriptRequest, HttpScriptResponse, ScriptError};
