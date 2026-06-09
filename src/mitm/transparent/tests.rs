//! # `mitm::transparent::tests`
//!
//! **Purpose**: Covers transparent URI reconstruction and upstream origin-form conversion.
//! **Public API**: test-only
//! **Dependencies**: `mitm::transparent`, `http-mitm-proxy`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 90 / 100

use bytes::Bytes;
use http_body_util::Full;
use http_mitm_proxy::hyper::{header::HOST, http::HeaderMap, Request};

use super::{upstream::strip_request_authority, uri::transparent_authority, TransparentUpstream};
use crate::{divert::OriginalDest, mitm::header_value};

#[test]
fn transparent_authority_uses_host_header_for_default_port() {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, "example.com".parse().expect("host header"));
    let upstream = transparent_test_upstream(443, "https");

    let authority =
        transparent_authority(&"/".parse().expect("uri"), &headers, &upstream).expect("authority");

    assert_eq!(authority.as_str(), "example.com");
}

#[test]
fn transparent_authority_keeps_non_default_port() {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, "example.com".parse().expect("host header"));
    let upstream = transparent_test_upstream(8443, "https");

    let authority =
        transparent_authority(&"/".parse().expect("uri"), &headers, &upstream).expect("authority");

    assert_eq!(authority.as_str(), "example.com:8443");
}

#[test]
fn transparent_authority_falls_back_to_original_ip() {
    let headers = HeaderMap::new();
    let upstream = transparent_test_upstream(8080, "http");

    let authority =
        transparent_authority(&"/".parse().expect("uri"), &headers, &upstream).expect("authority");

    assert_eq!(authority.as_str(), "93.184.216.34:8080");
}

#[test]
fn transparent_authority_uses_tls_sni_hint_without_host_header() {
    let headers = HeaderMap::new();
    let upstream = TransparentUpstream {
        host_hint: Some("example.com".into()),
        ..transparent_test_upstream(443, "https")
    };

    let authority =
        transparent_authority(&"/".parse().expect("uri"), &headers, &upstream).expect("authority");

    assert_eq!(authority.as_str(), "example.com");
}

#[test]
fn strip_request_authority_leaves_origin_form() {
    let req = Request::builder()
        .uri("https://example.com:443/path?q=1")
        .body(Full::new(Bytes::new()))
        .expect("request");

    let req = strip_request_authority(req).expect("strip authority");

    assert_eq!(req.uri().to_string(), "/path?q=1");
    assert_eq!(header_value(req.headers(), HOST), Some("example.com:443"));
}

fn transparent_test_upstream(port: u16, scheme: &'static str) -> TransparentUpstream {
    TransparentUpstream {
        dest: OriginalDest {
            ip: "93.184.216.34".parse().expect("ip"),
            port,
            pid: 4242,
        },
        scheme,
        host_hint: None,
    }
}
