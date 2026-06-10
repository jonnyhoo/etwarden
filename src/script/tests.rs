//! # `script::tests`
//!
//! **Purpose**: Unit tests for Lua script callback execution.
//! **Public API**: test module only
//! **Dependencies**: `script`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 101 / 140

use super::*;

#[test]
fn http_request_callback_mutates_request() {
    let engine = ScriptEngine::from_source(
        r#"
        function on_http_request(req)
            req.method = "POST"
            req.url = req.url .. "?script=1"
            req.headers["X-Etwarden"] = "captured"
            req.body = "changed"
        end
        "#,
    )
    .expect("script loads");
    let mut request = HttpScriptRequest::new("GET", "https://example.com/path");
    request.headers.insert("Host".into(), "example.com".into());
    request.body = b"old".to_vec();

    let decision = engine.on_http_request(&mut request).expect("callback");

    assert_eq!(decision, HttpScriptDecision::Continue);
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "https://example.com/path?script=1");
    assert_eq!(
        request.headers.get("X-Etwarden").map(String::as_str),
        Some("captured")
    );
    assert_eq!(request.body, b"changed");
}

#[test]
fn http_request_callback_can_drop_request() {
    let engine = ScriptEngine::from_source(
        r#"
        function on_http_request(req)
            if req.url:find("ads%.example%.com") then
                req.drop = true
            end
        end
        "#,
    )
    .expect("script loads");
    let mut request = HttpScriptRequest::new("GET", "https://ads.example.com/banner");

    let decision = engine.on_http_request(&mut request).expect("callback");

    assert_eq!(decision, HttpScriptDecision::Drop);
    assert!(request.drop);
}

#[test]
fn missing_http_request_callback_is_noop() {
    let engine = ScriptEngine::from_source("value = 1").expect("script loads");
    let mut request = HttpScriptRequest::new("GET", "https://example.com");
    request.body = b"body".to_vec();

    let decision = engine.on_http_request(&mut request).expect("callback");

    assert_eq!(decision, HttpScriptDecision::Continue);
    assert_eq!(request.method, "GET");
    assert_eq!(request.url, "https://example.com");
    assert_eq!(request.body, b"body");
}

#[test]
fn invalid_http_request_callback_type_is_rejected() {
    let engine = ScriptEngine::from_source("on_http_request = 42").expect("script loads");
    let mut request = HttpScriptRequest::new("GET", "https://example.com");

    let err = engine
        .on_http_request(&mut request)
        .expect_err("callback type");

    assert!(matches!(
        err,
        ScriptError::InvalidCallback {
            name: "on_http_request",
            actual: "integer"
        }
    ));
}

#[test]
fn sandbox_disables_print_stdout() {
    let Err(err) = ScriptEngine::from_source("print('pollute stdout')") else {
        unreachable!("print disabled")
    };

    assert!(matches!(err, ScriptError::Lua(_)));
}
