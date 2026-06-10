//! # `output::schema::convert::http_payload::tests`
//!
//! **Purpose**: Unit tests for agent-friendly HTTP payload projection.
//! **Public API**: test module only
//! **Dependencies**: `output::schema::convert::http_payload`, `base64`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 61 / 120

use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::*;

#[test]
fn projects_json_body_for_agents() {
    let body = STANDARD.encode(br#"{"ok":true}"#);
    let projected = project_http_payload(None, Some(&body), false, Some("application/json"));

    assert_eq!(projected.body_format.as_deref(), Some("json"));
    assert_eq!(projected.body_text.as_deref(), Some(r#"{"ok":true}"#));
    assert_eq!(projected.body_json.expect("json")["ok"], true);
}

#[test]
fn keeps_truncated_json_as_text_fragment() {
    let body = STANDARD.encode(br#"{"ok""#);
    let projected = project_http_payload(None, Some(&body), true, Some("application/json"));

    assert_eq!(projected.body_format.as_deref(), Some("text"));
    assert_eq!(projected.body_json, None);
}

#[test]
fn keeps_truncated_sse_as_text_fragment() {
    let projected = project_http_payload(
        None,
        Some(&STANDARD.encode("event: message_start\ndata: {\"type\"")),
        true,
        Some("text/event-stream"),
    );

    assert_eq!(projected.body_format.as_deref(), Some("text"));
    assert!(projected.sse_events.is_empty());
}

#[test]
fn projects_sse_data_json() {
    let body = STANDARD.encode("event: message_start\ndata: {\"type\":\"message_start\"}\n\n");
    let projected = project_http_payload(None, Some(&body), false, Some("text/event-stream"));

    assert_eq!(projected.body_format.as_deref(), Some("sse"));
    assert_eq!(
        projected.sse_events[0].event.as_deref(),
        Some("message_start")
    );
    assert_eq!(
        projected.sse_events[0].data_json.as_ref().expect("json")["type"],
        "message_start"
    );
}
