//! # `output::schema::convert::tests`
//!
//! **Purpose**: Facade for schema conversion unit tests.
//! **Public API**: test module only
//! **Dependencies**: `output::schema::convert`, `chrono`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 24 / 80

use chrono::{DateTime, Utc};

fn test_timestamp() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .map(|dt| dt.with_timezone(&Utc))
        .expect("valid timestamp")
}

mod dns;
mod http;
mod network;
