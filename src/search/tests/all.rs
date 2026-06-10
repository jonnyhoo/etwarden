//! # `search::tests::all`
//!
//! **Purpose**: Unit tests for aggregated payload search.
//! **Public API**: test module only
//! **Dependencies**: `search`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 41 / 200

use super::{search_all, CapturedPayload, SearchError, SearchType};

#[test]
fn search_all_preserves_request_ids_and_offsets() {
    let payloads = [
        CapturedPayload {
            request_id: 7,
            payload: b"abc abc",
        },
        CapturedPayload {
            request_id: 9,
            payload: b"xxabc",
        },
    ];

    let results = search_all(&payloads, "abc", SearchType::Utf8, true).expect("search");

    assert_eq!(
        results
            .iter()
            .map(|hit| (hit.request_id, hit.offset, hit.length))
            .collect::<Vec<_>>(),
        vec![(7, 0, 3), (7, 4, 3), (9, 2, 3)]
    );
}

#[test]
fn search_all_rejects_invalid_query_without_payloads() {
    let err = search_all(&[], "f", SearchType::Hex, true).expect_err("hex");

    assert!(matches!(err, SearchError::InvalidHexLength { .. }));
}
