//! # `search::tests::numeric`
//!
//! **Purpose**: Unit tests for numeric payload search types.
//! **Public API**: test module only
//! **Dependencies**: `search`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 74 / 200

use super::{offsets, search_payload, SearchError, SearchType};

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
fn float32_search_finds_big_and_little_endian_encodings() {
    let be = 42.5_f32.to_be_bytes();
    let le = 42.5_f32.to_le_bytes();
    let payload = [be.as_slice(), le.as_slice()].concat();

    let results = search_payload(&payload, "42.5", SearchType::Float32, true).expect("search");

    assert_eq!(offsets(&results), vec![0, 4]);
    assert!(results.iter().all(|hit| hit.length == 4));
}

#[test]
fn float64_search_finds_big_and_little_endian_encodings() {
    let be = 42.5_f64.to_be_bytes();
    let le = 42.5_f64.to_le_bytes();
    let payload = [be.as_slice(), le.as_slice()].concat();

    let results = search_payload(&payload, "42.5", SearchType::Float64, true).expect("search");

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
fn invalid_float_queries_are_rejected() {
    let float32 =
        search_payload(b"abc", "not-a-float", SearchType::Float32, true).expect_err("float32");
    let float64 =
        search_payload(b"abc", "not-a-float", SearchType::Float64, true).expect_err("float64");

    assert!(matches!(float32, SearchError::InvalidFloat32 { .. }));
    assert!(matches!(float64, SearchError::InvalidFloat64 { .. }));
}
