//! # `script::engine`
//!
//! **Purpose**: Loads sandboxed Lua scripts and runs traffic callbacks.
//! **Public API**: `ScriptEngine`
//! **Dependencies**: `mlua`, `script::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 192 / 200

use mlua::{Lua, LuaOptions, StdLib, Table, Value};

use super::{HttpScriptDecision, HttpScriptRequest, ScriptError};

const HTTP_REQUEST_CALLBACK: &str = "on_http_request";
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
        let callback = self.lua.globals().get::<Value>(HTTP_REQUEST_CALLBACK)?;
        let Value::Function(callback) = callback else {
            return callback_decision(callback, HTTP_REQUEST_CALLBACK);
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

fn callback_decision(value: Value, name: &'static str) -> Result<HttpScriptDecision, ScriptError> {
    match value {
        Value::Nil => Ok(HttpScriptDecision::Continue),
        other => Err(ScriptError::InvalidCallback {
            name,
            actual: other.type_name(),
        }),
    }
}

fn request_to_table(lua: &Lua, request: &HttpScriptRequest) -> Result<Table, mlua::Error> {
    let table = lua.create_table()?;
    table.set("method", request.method.as_str())?;
    table.set("url", request.url.as_str())?;
    table.set("headers", headers_to_table(lua, &request.headers)?)?;
    table.set("body", lua.create_string(&request.body)?)?;
    table.set("drop", request.drop)?;
    Ok(table)
}

fn headers_to_table(
    lua: &Lua,
    headers: &std::collections::BTreeMap<String, String>,
) -> Result<Table, mlua::Error> {
    let table = lua.create_table()?;
    for (name, value) in headers {
        table.set(name.as_str(), value.as_str())?;
    }
    Ok(table)
}

fn update_request_from_table(
    request: &mut HttpScriptRequest,
    table: &Table,
) -> Result<(), ScriptError> {
    request.method = string_field(table, "method")?;
    request.url = string_field(table, "url")?;
    request.headers = headers_field(table)?;
    request.body = body_field(table)?;
    request.drop = bool_field(table, "drop")?;
    Ok(())
}

fn string_field(table: &Table, field: &'static str) -> Result<String, ScriptError> {
    match table.get::<Value>(field)? {
        Value::String(value) => Ok(value.to_str()?.to_owned()),
        other => Err(invalid_type(field, "string", other.type_name())),
    }
}

fn headers_field(table: &Table) -> Result<std::collections::BTreeMap<String, String>, ScriptError> {
    match table.get::<Value>("headers")? {
        Value::Nil => Ok(std::collections::BTreeMap::new()),
        Value::Table(headers) => headers_from_table(&headers),
        other => Err(invalid_type("headers", "table or nil", other.type_name())),
    }
}

fn headers_from_table(
    table: &Table,
) -> Result<std::collections::BTreeMap<String, String>, ScriptError> {
    let mut headers = std::collections::BTreeMap::new();
    for pair in table.pairs::<Value, Value>() {
        let (key, value) = pair?;
        let key = lua_string(key, "headers.<key>")?;
        let value = lua_string(value, "headers.<value>")?;
        headers.insert(key, value);
    }
    Ok(headers)
}

fn body_field(table: &Table) -> Result<Vec<u8>, ScriptError> {
    match table.get::<Value>("body")? {
        Value::Nil => Ok(Vec::new()),
        Value::String(value) => Ok(value.as_bytes().to_vec()),
        other => Err(invalid_type("body", "string or nil", other.type_name())),
    }
}

fn bool_field(table: &Table, field: &'static str) -> Result<bool, ScriptError> {
    match table.get::<Value>(field)? {
        Value::Nil => Ok(false),
        Value::Boolean(value) => Ok(value),
        other => Err(invalid_type(field, "boolean or nil", other.type_name())),
    }
}

fn lua_string(value: Value, field: &'static str) -> Result<String, ScriptError> {
    match value {
        Value::String(value) => Ok(value.to_str()?.to_owned()),
        other => Err(invalid_type(field, "string", other.type_name())),
    }
}

fn invalid_type(
    field: impl Into<String>,
    expected: &'static str,
    actual: &'static str,
) -> ScriptError {
    ScriptError::InvalidFieldType {
        field: field.into(),
        expected,
        actual,
    }
}
