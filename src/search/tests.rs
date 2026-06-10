//! # `search::tests`
//!
//! **Purpose**: Unit tests for payload search primitives.
//! **Public API**: test module only
//! **Dependencies**: `search`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 79 / 90

use super::*;

mod numeric;

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
fn gbk_search_encodes_query() {
    let results =
        search_payload(&[0xD6, 0xD0, 0xCE, 0xC4], "中文", SearchType::Gbk, true).expect("search");

    assert_eq!(results[0].offset, 0);
}

#[test]
fn gbk_search_rejects_unencodable_query() {
    let err = search_payload(b"abc", "😀", SearchType::Gbk, true).expect_err("gbk");

    assert!(matches!(err, SearchError::InvalidGbk { .. }));
}

#[test]
fn empty_query_is_rejected() {
    let err = search_payload(b"abc", "", SearchType::Utf8, true).expect_err("empty query");

    assert!(matches!(err, SearchError::EmptyQuery));
}
