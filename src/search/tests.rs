//! # `search::tests`
//!
//! **Purpose**: Unit tests for payload search primitives.
//! **Public API**: test module only
//! **Dependencies**: `search`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 90 / 90

use super::*;

fn offsets(r: &[SearchResult]) -> Vec<usize> {
    r.iter().map(|hit| hit.offset).collect()
}
#[test]
fn utf8_search_finds_all_offsets_with_context() {
    let results = search_payload(b"abc--abc", "abc", SearchType::Utf8, true).expect("search");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].length, 3);
    assert_eq!(results[0].context, b"abc--abc");
    assert_eq!(results[1].offset, 5);
}

#[test]
fn utf8_search_can_ignore_ascii_case() {
    let results = search_payload(b"Host: Example.COM", "example.com", SearchType::Utf8, false)
        .expect("search");

    assert_eq!(results[0].offset, 6);
}

#[test]
fn byte_search_finds_overlapping_matches() {
    let results = search_payload(b"aaaa", "aa", SearchType::Utf8, true).expect("search");

    assert_eq!(offsets(&results), vec![0, 1, 2]);
}

#[test]
fn hex_search_ignores_whitespace() {
    let results = search_payload(b"abc", "61 62", SearchType::Hex, true).expect("search");

    assert_eq!(results[0].offset, 0);
}

#[test]
fn base64_search_decodes_query() {
    let results = search_payload(b"prefix token suffix", "dG9rZW4=", SearchType::Base64, true)
        .expect("search");

    assert_eq!(results[0].offset, 7);
}

#[test]
fn int32_search_finds_big_and_little_endian_encodings() {
    let payload = [0, 0, 0, 42, 42, 0, 0, 0];

    let results = search_payload(&payload, "42", SearchType::Int32, true).expect("search");

    assert_eq!(offsets(&results), vec![0, 4]);
    assert!(results.iter().all(|hit| hit.length == 4));
}

#[test]
fn int64_search_finds_big_and_little_endian_encodings() {
    let payload = [0, 0, 0, 0, 0, 0, 0, 42, 42, 0, 0, 0, 0, 0, 0, 0];

    let results = search_payload(&payload, "42", SearchType::Int64, true).expect("search");

    assert_eq!(offsets(&results), vec![0, 8]);
    assert!(results.iter().all(|hit| hit.length == 8));
}

#[test]
fn invalid_integer_queries_are_rejected() {
    let int32 = search_payload(b"abc", "not-an-int", SearchType::Int32, true).expect_err("int32");
    let int64 = search_payload(b"abc", "not-an-int", SearchType::Int64, true).expect_err("int64");

    assert!(matches!(int32, SearchError::InvalidInt32 { .. }));
    assert!(matches!(int64, SearchError::InvalidInt64 { .. }));
}

#[test]
fn empty_query_is_rejected() {
    let err = search_payload(b"abc", "", SearchType::Utf8, true).expect_err("empty query");

    assert!(matches!(err, SearchError::EmptyQuery));
}
