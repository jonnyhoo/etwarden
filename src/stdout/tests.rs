//! # `stdout::tests`
//!
//! **Purpose**: Unit tests for binary NDJSON writer.
//! **Public API**: test module only
//! **Dependencies**: `stdout`, `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 25 / 80

use etwarden::output::schema::ErrorLine;

use super::*;

#[test]
fn output_error_line_is_ndjson() {
    let mut buf = Vec::new();
    let output = OutputLine::Error(ErrorLine::new("capture failed"));
    write_output_line_to(&mut buf, &output).expect("write");
    let line = String::from_utf8(buf).expect("utf8");
    assert_eq!(
        line,
        "{\"type\":\"error\",\"message\":\"capture failed\"}\n"
    );
}
