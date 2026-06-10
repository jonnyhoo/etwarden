//! # `script::tests`
//!
//! **Purpose**: Unit tests for Lua script callback execution.
//! **Public API**: test module only
//! **Dependencies**: `script`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 167 / 200

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
fn http_response_callback_mutates_response() {
    let engine = ScriptEngine::from_source(
        r#"
        function on_http_response(req, resp)
            if req.url:find("/html") then
                resp.status_code = 201
                resp.headers["Content-Type"] = "text/html"
                resp.body = resp.body:gsub("</head>", "<!-- etwarden --></head>")
            end
        end
        "#,
    )
    .expect("script loads");
    let request = HttpScriptRequest::new("GET", "https://example.com/html");
    let mut response = HttpScriptResponse::new(200);
    response.body = b"<html><head></head></html>".to_vec();

    engine
        .on_http_response(&request, &mut response)
        .expect("callback");

    assert_eq!(response.status_code, 201);
    assert_eq!(
        response.headers.get("Content-Type").map(String::as_str),
        Some("text/html")
    );
    assert_eq!(
        response.body,
        b"<html><head><!-- etwarden --></head></html>"
    );
}

#[test]
fn missing_http_response_callback_is_noop() {
    let engine = ScriptEngine::from_source("value = 1").expect("script loads");
    let request = HttpScriptRequest::new("GET", "https://example.com");
    let mut response = HttpScriptResponse::new(204);
    response.body = b"body".to_vec();

    engine
        .on_http_response(&request, &mut response)
        .expect("callback");

    assert_eq!(response.status_code, 204);
    assert_eq!(response.body, b"body");
}

#[test]
fn invalid_http_response_callback_type_is_rejected() {
    let engine = ScriptEngine::from_source("on_http_response = 'bad'").expect("script loads");
    let request = HttpScriptRequest::new("GET", "https://example.com");
    let mut response = HttpScriptResponse::new(200);

    let err = engine
        .on_http_response(&request, &mut response)
        .expect_err("callback type");

    assert!(matches!(
        err,
        ScriptError::InvalidCallback {
            name: "on_http_response",
            actual: "string"
        }
    ));
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
