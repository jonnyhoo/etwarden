//! # `parser::dpi::tls::tests`
//!
//! **Purpose**: Unit tests for TLS ClientHello metadata parsing.
//! **Public API**: test module only
//! **Dependencies**: `parser::dpi::tls`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 208 / 240

use super::*;

#[test]
fn tls_handshake_detected() {
    assert!(is_tls_handshake(&[0x16, 0x03, 0x01, 0x00, 0x05]));
    assert!(!is_tls_handshake(&[0x17, 0x03, 0x01, 0x00, 0x05]));
}

#[test]
fn tls_client_hello_with_sni_detected() {
    let result =
        analyze_tls_hello(&build_tls_client_hello("example.com")).expect("should parse tls hello");

    assert_eq!(result.sni.as_deref(), Some("example.com"));
    assert_eq!(result.version.as_deref(), Some("TLS 1.2"));
    assert!(result.alpn.is_empty());
    assert_eq!(result.cipher_count, 1);
    assert_eq!(result.extension_count, 1);
}

#[test]
fn tls_client_hello_extracts_alpn_and_supported_version() {
    let result = analyze_tls_hello(&build_tls_client_hello_with_extra_extensions("example.com"))
        .expect("should parse tls hello");

    assert_eq!(result.sni.as_deref(), Some("example.com"));
    assert_eq!(result.version.as_deref(), Some("TLS 1.3"));
    assert_eq!(result.ja3, "771,4865,0-16-43,,");
    assert_eq!(result.ja3_hash, "9cd3a3df22ead6ac1977bf836d6ea964");
    assert_eq!(result.ja3n, "771,4865,0-16-43,,");
    assert_eq!(result.ja3n_hash, "9cd3a3df22ead6ac1977bf836d6ea964");
    assert_eq!(result.ja4, "t13d0103h2_0f2cb44170f4_4835ae301cc7");
    assert_eq!(result.ja4o, "t13d0103h2_0f2cb44170f4_4835ae301cc7");
    assert_eq!(result.ja4r, "t13d0103h2_1301_00000010002b_");
    assert_eq!(result.ja4ro, "t13d0103h2_1301_00000010002b_");
    assert_eq!(result.alpn, vec!["h2", "http/1.1"]);
    assert_eq!(result.cipher_count, 1);
    assert_eq!(result.extension_count, 3);
}

#[test]
fn tls_rejects_truncated_record_length() {
    let mut payload = build_tls_client_hello("example.com");
    let declared = u16::try_from(payload.len() - 4).expect("fits in u16");
    payload[3..5].copy_from_slice(&declared.to_be_bytes());
    payload.truncate(payload.len() - 2);

    assert!(analyze_tls_hello(&payload).is_none());
}

#[test]
fn tls_rejects_cipher_suites_past_handshake_length() {
    let mut payload = build_tls_client_hello("example.com");
    let cipher_len_offset = 44;
    payload[cipher_len_offset..cipher_len_offset + 2].copy_from_slice(&0xfffe_u16.to_be_bytes());

    assert!(analyze_tls_hello(&payload).is_none());
}

#[test]
fn tls_rejects_extension_past_declared_length() {
    let mut payload = build_tls_client_hello("example.com");
    let ext_len_offset = 54;
    let declared = u16::from_be_bytes([payload[ext_len_offset], payload[ext_len_offset + 1]]);
    payload[ext_len_offset..ext_len_offset + 2]
        .copy_from_slice(&declared.saturating_add(1).to_be_bytes());

    assert!(analyze_tls_hello(&payload).is_none());
}

#[test]
fn tls_does_not_extract_sni_when_list_length_mismatches() {
    let mut payload = build_tls_client_hello("example.com");
    payload[56..58].copy_from_slice(&1u16.to_be_bytes());

    let result = analyze_tls_hello(&payload).expect("still valid tls");
    assert!(result.sni.is_none());
}

#[test]
fn tls_does_not_extract_non_hostname_sni_entry() {
    let mut payload = build_tls_client_hello("example.com");
    payload[58] = 1;

    let result = analyze_tls_hello(&payload).expect("still valid tls");
    assert!(result.sni.is_none());
}

#[test]
fn tls_does_not_extract_invalid_utf8_sni() {
    let mut payload = build_tls_client_hello("example.com");
    payload[61] = 0xFF;

    let result = analyze_tls_hello(&payload).expect("still valid tls");
    assert!(result.sni.is_none());
}

fn build_tls_client_hello(host: &str) -> Vec<u8> {
    let sni = sni_extension(host);
    let extensions = vec![(0u16, sni)];
    build_tls_client_hello_with_extensions(&extensions)
}

fn build_tls_client_hello_with_extra_extensions(host: &str) -> Vec<u8> {
    let extensions = vec![
        (0u16, sni_extension(host)),
        (16u16, alpn_extension(&["h2", "http/1.1"])),
        (
            43u16,
            supported_versions_extension(&[0x0a0a, 0x0304, 0x0303]),
        ),
    ];
    build_tls_client_hello_with_extensions(&extensions)
}

fn sni_extension(host: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&[0x00, 0x00]);
    sni.push(0x00);
    sni.extend_from_slice(
        &u16::try_from(host.len())
            .expect("host length fits")
            .to_be_bytes(),
    );
    sni.extend_from_slice(host.as_bytes());
    let list_len = u16::try_from(sni.len() - 2)
        .expect("sni list length fits")
        .to_be_bytes();
    sni[0..2].copy_from_slice(&list_len);
    sni
}

fn alpn_extension(protocols: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        list.push(u8::try_from(protocol.len()).expect("protocol length fits"));
        list.extend_from_slice(protocol.as_bytes());
    }

    let mut data = Vec::new();
    data.extend_from_slice(
        &u16::try_from(list.len())
            .expect("alpn list length fits")
            .to_be_bytes(),
    );
    data.extend_from_slice(&list);
    data
}

fn supported_versions_extension(versions: &[u16]) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(u8::try_from(versions.len() * 2).expect("versions length fits"));
    for version in versions {
        data.extend_from_slice(&version.to_be_bytes());
    }
    data
}

fn build_tls_client_hello_with_extensions(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut encoded_extensions = Vec::new();
    for (extension_type, extension_data) in extensions {
        encoded_extensions.extend_from_slice(&extension_type.to_be_bytes());
        encoded_extensions.extend_from_slice(
            &u16::try_from(extension_data.len())
                .expect("extension length fits")
                .to_be_bytes(),
        );
        encoded_extensions.extend_from_slice(extension_data);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(
        &u16::try_from(encoded_extensions.len())
            .expect("extensions length fits")
            .to_be_bytes(),
    );
    body.extend_from_slice(&encoded_extensions);

    let mut payload = vec![0x16, 0x03, 0x03];
    let record_len = 4 + body.len();
    payload.extend_from_slice(
        &u16::try_from(record_len)
            .expect("record length fits")
            .to_be_bytes(),
    );
    payload.push(0x01);
    let handshake_len = u32::try_from(body.len()).expect("handshake length fits");
    payload.extend_from_slice(&handshake_len.to_be_bytes()[1..4]);
    payload.extend_from_slice(&body);
    payload
}
