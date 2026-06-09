//! # `output::schema::convert::http_payload`
//!
//! **Purpose**: Projects captured HTTP bytes into agent-friendly plaintext fields.
//! **Public API**: module-private payload projection helpers
//! **Dependencies**: `base64`, `serde_json`, `output::schema`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 128 / 160

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

use crate::output::schema::{HttpHeaderLine, HttpSseEventLine};

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct HttpPayloadProjection {
    pub headers: Vec<HttpHeaderLine>,
    pub body_format: Option<String>,
    pub body_text: Option<String>,
    pub body_json: Option<Value>,
    pub sse_events: Vec<HttpSseEventLine>,
}

pub(super) fn project_http_payload(
    headers_base64: Option<&str>,
    body_base64: Option<&str>,
    body_truncated: bool,
    content_type: Option<&str>,
) -> HttpPayloadProjection {
    let headers = headers_base64
        .and_then(decode_base64_utf8)
        .map_or_else(Vec::new, |text| parse_headers(&text));
    let body_text = body_base64.and_then(decode_base64_utf8);
    let body_json = body_text
        .as_deref()
        .filter(|_| !body_truncated)
        .and_then(parse_json_body);
    let sse_events = if is_sse(content_type) {
        body_text.as_deref().map_or_else(Vec::new, parse_sse_events)
    } else {
        Vec::new()
    };
    let body_format = body_format(body_base64, body_text.as_deref(), &body_json, &sse_events);

    HttpPayloadProjection {
        headers,
        body_format,
        body_text,
        body_json,
        sse_events,
    }
}

fn decode_base64_utf8(value: &str) -> Option<String> {
    String::from_utf8(STANDARD.decode(value).ok()?).ok()
}

fn parse_headers(text: &str) -> Vec<HttpHeaderLine> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.trim_end_matches('\r').split_once(':')?;
            Some(HttpHeaderLine {
                name: name.trim().to_owned(),
                value: value.trim_start().to_owned(),
            })
        })
        .collect()
}

fn parse_json_body(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn parse_sse_events(text: &str) -> Vec<HttpSseEventLine> {
    let mut events = Vec::new();
    let mut event_name = None;
    let mut data_lines = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            flush_sse_event(&mut events, &mut event_name, &mut data_lines);
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event_name = Some(trim_sse_value(value).to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(trim_sse_value(value).to_owned());
        }
    }
    flush_sse_event(&mut events, &mut event_name, &mut data_lines);
    events
}

fn flush_sse_event(
    events: &mut Vec<HttpSseEventLine>,
    event_name: &mut Option<String>,
    data_lines: &mut Vec<String>,
) {
    if event_name.is_none() && data_lines.is_empty() {
        return;
    }
    let data = data_lines.join("\n");
    let data_json = serde_json::from_str(&data).ok();
    events.push(HttpSseEventLine {
        event: event_name.take(),
        data,
        data_json,
    });
    data_lines.clear();
}

fn trim_sse_value(value: &str) -> &str {
    value.strip_prefix(' ').unwrap_or(value)
}

fn is_sse(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
    })
}

fn body_format(
    body_base64: Option<&str>,
    body_text: Option<&str>,
    body_json: &Option<Value>,
    sse_events: &[HttpSseEventLine],
) -> Option<String> {
    if body_json.is_some() {
        Some("json".into())
    } else if !sse_events.is_empty() {
        Some("sse".into())
    } else if body_text.is_some() {
        Some("text".into())
    } else if body_base64.is_some() {
        Some("base64".into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
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
}
