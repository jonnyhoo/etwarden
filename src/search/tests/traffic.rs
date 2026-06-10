//! # `search::tests::traffic`
//!
//! **Purpose**: Unit tests for captured traffic search.
//! **Public API**: test module only
//! **Dependencies**: `search`, `base64`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 147 / 200

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};

use super::{
    search_traffic, CapturedTraffic, SearchError, SearchType, TrafficPayloadKind,
    TrafficSearchError,
};
use crate::parser::types::NetEvent;

#[test]
fn traffic_search_decodes_decrypted_http_body() {
    let event = decrypted_request(None, Some(b"hello token"));
    let traffic = [CapturedTraffic {
        record_id: 42,
        event: &event,
    }];

    let results = search_traffic(&traffic, "token", SearchType::Utf8, true).expect("search");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].record_id, 42);
    assert_eq!(results[0].payload_kind, TrafficPayloadKind::HttpBody);
    assert_eq!(results[0].offset, 6);
    assert_eq!(results[0].length, 5);
    assert_eq!(results[0].context, b"hello token");
}

#[test]
fn traffic_search_preserves_record_and_segment_order() {
    let first = decrypted_request(Some(b"x-token: one\r\n"), Some(b"body"));
    let second = tunnel_data(None, Some(b"xxonetwo"));
    let traffic = [
        CapturedTraffic {
            record_id: 7,
            event: &first,
        },
        CapturedTraffic {
            record_id: 9,
            event: &second,
        },
    ];

    let results = search_traffic(&traffic, "one", SearchType::Utf8, true).expect("search");

    assert_eq!(
        results
            .iter()
            .map(|hit| (hit.record_id, hit.payload_kind, hit.offset))
            .collect::<Vec<_>>(),
        vec![
            (7, TrafficPayloadKind::HttpHeaders, 9),
            (9, TrafficPayloadKind::TunnelPayload, 2),
        ]
    );
}

#[test]
fn traffic_search_rejects_invalid_query_without_payloads() {
    let err = search_traffic(&[], "f", SearchType::Hex, true).expect_err("hex");

    assert!(matches!(
        err,
        TrafficSearchError::Search(SearchError::InvalidHexLength { .. })
    ));
}

#[test]
fn traffic_search_reports_invalid_base64_segment() {
    let event = invalid_decrypted_request();
    let traffic = [CapturedTraffic {
        record_id: 5,
        event: &event,
    }];

    let err = search_traffic(&traffic, "token", SearchType::Utf8, true).expect_err("base64");

    assert!(matches!(
        err,
        TrafficSearchError::PayloadDecode {
            record_id: 5,
            payload_kind: TrafficPayloadKind::HttpBody,
            ..
        }
    ));
}

fn ts() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .map(|dt| dt.with_timezone(&Utc))
        .expect("valid timestamp")
}

fn decrypted_request(headers: Option<&[u8]>, body: Option<&[u8]>) -> NetEvent {
    NetEvent::DecryptedHttpRequest {
        timestamp: ts(),
        pid: 1234,
        src: "127.0.0.1:50000".into(),
        dst: "127.0.0.1:3003".into(),
        method: "POST".into(),
        path: "/v1/messages".into(),
        host: Some("localhost".into()),
        version: "HTTP/1.1".into(),
        headers_base64: headers.map(|value| STANDARD.encode(value)),
        headers_truncated: false,
        content_type: Some("application/json".into()),
        content_length: None,
        content_encoding: None,
        decoded: true,
        body_base64: body.map(|value| STANDARD.encode(value)),
        body_truncated: false,
    }
}

fn invalid_decrypted_request() -> NetEvent {
    let mut event = decrypted_request(None, None);
    let NetEvent::DecryptedHttpRequest { body_base64, .. } = &mut event else {
        unreachable!("decrypted request")
    };
    *body_base64 = Some("not valid base64%%%".into());
    event
}

fn tunnel_data(headers: Option<&[u8]>, payload: Option<&[u8]>) -> NetEvent {
    NetEvent::TunnelData {
        timestamp: ts(),
        pid: 1234,
        src: "10.0.0.1:50000".into(),
        dst: "93.184.216.34:443".into(),
        direction: "request".into(),
        encrypted: false,
        headers_base64: headers.map(|value| STANDARD.encode(value)),
        headers_truncated: false,
        payload_base64: payload.map(|value| STANDARD.encode(value)),
        payload_truncated: false,
        bytes_seen: payload.map_or(0, |value| value.len() as u64),
        bytes_captured: payload.map_or(0, |value| value.len() as u64),
    }
}
