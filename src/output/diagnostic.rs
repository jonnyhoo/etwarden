//! # `output::diagnostic`
//!
//! **Purpose**: Centralizes stderr diagnostics so stdout stays NDJSON-only.
//! **Public API**: `write`, `warn`, `info`
//! **Dependencies**: `std::io`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 30 / 60

use std::{
    fmt,
    io::{self, Write},
};

/// Writes a raw diagnostic message to stderr without touching stdout.
///
/// # Errors
/// Returns any stderr write error.
pub fn write(message: fmt::Arguments<'_>) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    stderr.write_fmt(message)
}

/// Writes a prefixed warning line to stderr, dropping write errors.
pub fn warn(message: fmt::Arguments<'_>) {
    let _ = write(format_args!("[etwarden] {message}\n"));
}

/// Writes a prefixed info line to stderr, dropping write errors.
pub fn info(message: fmt::Arguments<'_>) {
    let _ = write(format_args!("[etwarden] {message}\n"));
}
