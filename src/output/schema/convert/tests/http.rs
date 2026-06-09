use super::test_timestamp;
use crate::{
    output::schema::{convert::*, OutputLine},
    parser::types::NetEvent,
};

#[test]
fn http_request_line_keeps_method_path_and_host() {
    let event = NetEvent::HttpRequest {
        timestamp: test_timestamp(),
        pid: 1234,
        src: "10.0.0.1:51000".into(),
        dst: "93.184.216.34:80".into(),
        method: "GET".into(),
        path: "/index.html".into(),
        host: Some("example.com".into()),
        version: "HTTP/1.1".into(),
        content_type: None,
        content_length: None,
    };
    let line = event_to_line(&event);
    let OutputLine::HttpEvent(line) = line else {
        unreachable!()
    };
    assert_eq!(line.event, "http_request");
    assert_eq!(line.method.as_deref(), Some("GET"));
    assert_eq!(line.path.as_deref(), Some("/index.html"));
    assert_eq!(line.host.as_deref(), Some("example.com"));
    assert_eq!(line.version, "HTTP/1.1");
    assert_eq!(line.status_code, None);
}

#[test]
fn http_response_line_keeps_status_and_content_headers() {
    let event = NetEvent::HttpResponse {
        timestamp: test_timestamp(),
        pid: 1234,
        src: "93.184.216.34:80".into(),
        dst: "10.0.0.1:51000".into(),
        status_line: "HTTP/1.1 200 OK".into(),
        host: None,
        version: "HTTP/1.1".into(),
        status_code: 200,
        content_type: Some("application/json".into()),
        content_length: Some(123),
    };
    let line = event_to_line(&event);
    let OutputLine::HttpEvent(line) = line else {
        unreachable!()
    };
    assert_eq!(line.event, "http_response");
    assert_eq!(line.status_line.as_deref(), Some("HTTP/1.1 200 OK"));
    assert_eq!(line.status_code, Some(200));
    assert_eq!(line.content_type.as_deref(), Some("application/json"));
    assert_eq!(line.content_length, Some(123));
}

#[test]
fn tls_hello_line_keeps_sni_and_version() {
    let event = NetEvent::TlsHello {
        timestamp: test_timestamp(),
        pid: 1234,
        src: "10.0.0.1:51000".into(),
        dst: "93.184.216.34:443".into(),
        sni: Some("example.com".into()),
        version: Some("TLS 1.2/1.3".into()),
        ja3: "771,4865,0,,".into(),
        ja3_hash: "hash-ja3".into(),
        ja3n: "771,4865,0,,".into(),
        ja3n_hash: "hash-ja3n".into(),
        ja4: "t13d010100_hash_hash".into(),
        ja4o: "t13d010100_hash_hash".into(),
        ja4r: "t13d010100_1301_0000_".into(),
        ja4ro: "t13d010100_1301_0000_".into(),
        alpn: vec!["h2".into()],
        cipher_count: 15,
        extension_count: 7,
    };
    let line = event_to_line(&event);
    let OutputLine::TlsEvent(line) = line else {
        unreachable!()
    };
    assert_eq!(line.event, "tls_hello");
    assert_eq!(line.sni.as_deref(), Some("example.com"));
    assert_eq!(line.tls_version.as_deref(), Some("TLS 1.2/1.3"));
    assert_eq!(line.ja3, "771,4865,0,,");
    assert_eq!(line.ja4, "t13d010100_hash_hash");
    assert_eq!(line.alpn, vec!["h2"]);
    assert_eq!(line.cipher_count, 15);
    assert_eq!(line.extension_count, 7);
}
