//! # `script::engine`
//!
//! **Purpose**: Loads sandboxed Lua scripts and runs traffic callbacks.
//! **Public API**: `ScriptEngine`
//! **Dependencies**: `mlua`, `script::{http, types}`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 133 / 200

use mlua::{Function, Lua, LuaOptions, StdLib, Value};

use super::{
    http::{
        request_to_table, response_to_table, update_request_from_table, update_response_from_table,
    },
    HttpScriptDecision, HttpScriptRequest, HttpScriptResponse, ScriptError,
};

const HTTP_REQUEST_CALLBACK: &str = "on_http_request";
const HTTP_RESPONSE_CALLBACK: &str = "on_http_response";
const SCRIPT_CHUNK_NAME: &str = "=etwarden-script";

/// Sandboxed Lua script engine.
pub struct ScriptEngine {
    lua: Lua,
}

impl ScriptEngine {
    /// Loads a Lua script into a sandboxed engine.
    ///
    /// # Arguments
    /// * `source` — Lua source defining optional callback functions.
    ///
    /// # Returns
    /// A script engine ready to run callbacks.
    ///
    /// # Errors
    /// Returns [`ScriptError`] when Lua initialization or source execution fails.
    pub fn from_source(source: &str) -> Result<Self, ScriptError> {
        let lua = Lua::new_with(StdLib::TABLE | StdLib::STRING, LuaOptions::default())?;
        install_sandbox_globals(&lua)?;
        lua.load(source).set_name(SCRIPT_CHUNK_NAME).exec()?;
        Ok(Self { lua })
    }

    /// Runs `on_http_request(req)` when defined.
    ///
    /// # Arguments
    /// * `request` — Mutable HTTP request view to expose to Lua.
    ///
    /// # Returns
    /// Script decision after applying Lua mutations.
    ///
    /// # Errors
    /// Returns [`ScriptError`] when callback lookup, callback execution, or field conversion fails.
    pub fn on_http_request(
        &self,
        request: &mut HttpScriptRequest,
    ) -> Result<HttpScriptDecision, ScriptError> {
        let Some(callback) = optional_callback(
            self.lua.globals().get::<Value>(HTTP_REQUEST_CALLBACK)?,
            HTTP_REQUEST_CALLBACK,
        )?
        else {
            return Ok(HttpScriptDecision::Continue);
        };

        let table = request_to_table(&self.lua, request)?;
        callback.call::<()>(table.clone())?;
        update_request_from_table(request, &table)?;
        Ok(if request.drop {
            HttpScriptDecision::Drop
        } else {
            HttpScriptDecision::Continue
        })
    }

    /// Runs `on_http_response(req, resp)` when defined.
    ///
    /// # Arguments
    /// * `request` — HTTP request view to expose to Lua.
    /// * `response` — Mutable HTTP response view to expose to Lua.
    ///
    /// # Errors
    /// Returns [`ScriptError`] when callback lookup, callback execution, or field conversion fails.
    pub fn on_http_response(
        &self,
        request: &HttpScriptRequest,
        response: &mut HttpScriptResponse,
    ) -> Result<(), ScriptError> {
        let Some(callback) = optional_callback(
            self.lua.globals().get::<Value>(HTTP_RESPONSE_CALLBACK)?,
            HTTP_RESPONSE_CALLBACK,
        )?
        else {
            return Ok(());
        };

        let request_table = request_to_table(&self.lua, request)?;
        let response_table = response_to_table(&self.lua, response)?;
        callback.call::<()>((request_table, response_table.clone()))?;
        update_response_from_table(response, &response_table)
    }
}

fn install_sandbox_globals(lua: &Lua) -> Result<(), mlua::Error> {
    let globals = lua.globals();
    for name in [
        "print",
        "dofile",
        "loadfile",
        "require",
        "collectgarbage",
        "io",
        "os",
        "package",
        "debug",
    ] {
        globals.set(name, Value::Nil)?;
    }
    Ok(())
}

fn optional_callback(value: Value, name: &'static str) -> Result<Option<Function>, ScriptError> {
    match value {
        Value::Nil => Ok(None),
        Value::Function(function) => Ok(Some(function)),
        other => Err(ScriptError::InvalidCallback {
            name,
            actual: other.type_name(),
        }),
    }
}
