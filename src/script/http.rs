//! # `script::http`
//!
//! **Purpose**: Converts HTTP script views to and from Lua tables.
//! **Public API**: module-private HTTP table conversion helpers
//! **Dependencies**: `mlua`, `script::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 141 / 200

use std::collections::BTreeMap;

use mlua::{Lua, Table, Value};

use super::{HttpScriptRequest, HttpScriptResponse, ScriptError};

pub(super) fn request_to_table(
    lua: &Lua,
    request: &HttpScriptRequest,
) -> Result<Table, mlua::Error> {
    let table = lua.create_table()?;
    table.set("method", request.method.as_str())?;
    table.set("url", request.url.as_str())?;
    table.set("headers", headers_to_table(lua, &request.headers)?)?;
    table.set("body", lua.create_string(&request.body)?)?;
    table.set("drop", request.drop)?;
    Ok(table)
}

pub(super) fn response_to_table(
    lua: &Lua,
    response: &HttpScriptResponse,
) -> Result<Table, mlua::Error> {
    let table = lua.create_table()?;
    table.set("status_code", response.status_code)?;
    table.set("headers", headers_to_table(lua, &response.headers)?)?;
    table.set("body", lua.create_string(&response.body)?)?;
    Ok(table)
}

pub(super) fn update_request_from_table(
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

pub(super) fn update_response_from_table(
    response: &mut HttpScriptResponse,
    table: &Table,
) -> Result<(), ScriptError> {
    response.status_code = status_code_field(table)?;
    response.headers = headers_field(table)?;
    response.body = body_field(table)?;
    Ok(())
}

fn headers_to_table(lua: &Lua, headers: &BTreeMap<String, String>) -> Result<Table, mlua::Error> {
    let table = lua.create_table()?;
    for (name, value) in headers {
        table.set(name.as_str(), value.as_str())?;
    }
    Ok(table)
}

fn string_field(table: &Table, field: &'static str) -> Result<String, ScriptError> {
    match table.get::<Value>(field)? {
        Value::String(value) => Ok(value.to_str()?.to_owned()),
        other => Err(invalid_type(field, "string", other.type_name())),
    }
}

fn headers_field(table: &Table) -> Result<BTreeMap<String, String>, ScriptError> {
    match table.get::<Value>("headers")? {
        Value::Nil => Ok(BTreeMap::new()),
        Value::Table(headers) => headers_from_table(&headers),
        other => Err(invalid_type("headers", "table or nil", other.type_name())),
    }
}

fn headers_from_table(table: &Table) -> Result<BTreeMap<String, String>, ScriptError> {
    let mut headers = BTreeMap::new();
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

fn status_code_field(table: &Table) -> Result<u16, ScriptError> {
    match table.get::<Value>("status_code")? {
        Value::Integer(value) => u16::try_from(value)
            .map_err(|_| invalid_type("status_code", "integer 0..=65535", "integer")),
        other => Err(invalid_type(
            "status_code",
            "integer 0..=65535",
            other.type_name(),
        )),
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
