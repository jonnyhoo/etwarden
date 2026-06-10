//! # `script::types`
//!
//! **Purpose**: Public data and error types for Lua scripting hooks.
//! **Public API**: `HttpScriptDecision`, `HttpScriptRequest`, `HttpScriptResponse`, `ScriptError`
//! **Dependencies**: `mlua`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 110 / 140

use std::collections::BTreeMap;

/// Mutable HTTP request view exposed to Lua callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpScriptRequest {
    /// HTTP method, e.g. `GET` or `POST`.
    pub method: String,
    /// Full request URL.
    pub url: String,
    /// Header map exposed as `req.headers`.
    pub headers: BTreeMap<String, String>,
    /// Raw request body exposed as Lua string bytes.
    pub body: Vec<u8>,
    /// Whether script requested dropping this request.
    pub drop: bool,
}

/// Mutable HTTP response view exposed to Lua callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpScriptResponse {
    /// HTTP status code exposed as `resp.status_code`.
    pub status_code: u16,
    /// Header map exposed as `resp.headers`.
    pub headers: BTreeMap<String, String>,
    /// Raw response body exposed as Lua string bytes.
    pub body: Vec<u8>,
}

/// HTTP request script decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpScriptDecision {
    /// Continue request handling with possible mutations.
    Continue,
    /// Drop the request.
    Drop,
}

/// Lua script engine error.
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// Lua loading, execution, or conversion failed.
    #[error(transparent)]
    Lua(#[from] mlua::Error),
    /// A configured callback global exists but is not callable.
    #[error("Lua callback `{name}` must be function or nil, got {actual}")]
    InvalidCallback {
        /// Callback global name.
        name: &'static str,
        /// Lua value type name.
        actual: &'static str,
    },
    /// Lua callback wrote a field with an unsupported type.
    #[error("Lua field `{field}` must be {expected}, got {actual}")]
    InvalidFieldType {
        /// Field path.
        field: String,
        /// Expected type description.
        expected: &'static str,
        /// Actual Lua type name.
        actual: &'static str,
    },
}

impl HttpScriptRequest {
    /// Creates an HTTP request script view.
    ///
    /// # Arguments
    /// * `method` — HTTP method.
    /// * `url` — Full request URL.
    ///
    /// # Returns
    /// A request view with empty headers/body and `drop = false`.
    #[must_use]
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
            drop: false,
        }
    }
}

impl HttpScriptResponse {
    /// Creates an HTTP response script view.
    ///
    /// # Arguments
    /// * `status_code` — HTTP status code.
    ///
    /// # Returns
    /// A response view with empty headers and body.
    #[must_use]
    pub const fn new(status_code: u16) -> Self {
        Self {
            status_code,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }
}
