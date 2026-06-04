//! # `parser::dpi::tls`
//!
//! **Purpose**: Detects TLS `ClientHello` metadata, including SNI, ALPN, and version hints.
//! **Public API**: `TlsInfo`
//! **Dependencies**: `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 250 / 360

mod extensions;
mod fingerprint;

use extensions::parse_extensions;
use fingerprint::{build_fingerprint, FingerprintInput};
use serde::Serialize;

/// TLS `ClientHello` information.
#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    /// Server Name Indication hostname extracted from `ClientHello`.
    pub sni: Option<String>,
    /// ALPN protocol list extracted from `ClientHello`.
    pub alpn: Vec<String>,
    /// TLS version string (e.g. "TLS 1.3").
    pub version: Option<String>,
    /// JA3 text fingerprint.
    pub ja3: String,
    /// JA3 MD5 hex digest.
    pub ja3_hash: String,
    /// JA3N text fingerprint with sorted extensions.
    pub ja3n: String,
    /// JA3N MD5 hex digest.
    pub ja3n_hash: String,
    /// JA4 fingerprint with sorted ciphers/extensions.
    pub ja4: String,
    /// JA4 original-order fingerprint.
    pub ja4o: String,
    /// JA4 raw sorted fingerprint.
    pub ja4r: String,
    /// JA4 raw original-order fingerprint.
    pub ja4ro: String,
    /// Number of cipher suites after GREASE filtering.
    pub cipher_count: usize,
    /// Number of extensions present in the `ClientHello` after GREASE filtering.
    pub extension_count: usize,
}

/// Check if the payload starts with a TLS record header (content type 22 = Handshake).
pub(super) fn is_tls_handshake(payload: &[u8]) -> bool {
    payload.len() >= 5
        && payload[0] == 0x16
        && payload[1] == 0x03
        && (0x01..=0x03).contains(&payload[2])
}

/// Parse TLS `ClientHello` to extract passive metadata.
pub(super) fn analyze_tls_hello(payload: &[u8]) -> Option<TlsInfo> {
    if payload.len() < 43 || !is_tls_handshake(payload) {
        return None;
    }

    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    let record_end = checked_end(5, record_len, payload.len())?;

    if payload[5] != 0x01 {
        return None;
    }

    let handshake_len =
        (usize::from(payload[6]) << 16) | (usize::from(payload[7]) << 8) | usize::from(payload[8]);
    let handshake_end = checked_end(9, handshake_len, record_end)?;

    let legacy_version = u16::from_be_bytes([payload[9], payload[10]]);
    let random_end = 11 + 32;
    if handshake_end <= random_end {
        return None;
    }

    let session_id_len = usize::from(payload[random_end]);
    let cipher_suites_start = random_end + 1 + session_id_len;
    if handshake_end <= cipher_suites_start + 1 {
        return None;
    }

    let cipher_suites_len = usize::from(u16::from_be_bytes([
        payload[cipher_suites_start],
        payload[cipher_suites_start + 1],
    ]));
    if cipher_suites_len % 2 != 0 {
        return None;
    }
    let cipher_suites = parse_u16_values(&payload[cipher_suites_start + 2..][..cipher_suites_len]);

    let compression_start = cipher_suites_start + 2 + cipher_suites_len;
    if handshake_end <= compression_start + 1 {
        return None;
    }

    let compression_len = usize::from(payload[compression_start]);
    let extensions_start = compression_start + 1 + compression_len;
    if handshake_end <= extensions_start + 2 {
        return None;
    }

    let extensions_len = usize::from(u16::from_be_bytes([
        payload[extensions_start],
        payload[extensions_start + 1],
    ]));
    let extensions_end = checked_end(extensions_start + 2, extensions_len, handshake_end)?;

    let extensions = parse_extensions(&payload[extensions_start + 2..extensions_end])?;
    let highest_version = highest_tls_version(legacy_version, &extensions.supported_versions);
    let fingerprint = build_fingerprint(FingerprintInput {
        legacy_version,
        highest_version,
        cipher_suites: &cipher_suites,
        extensions: &extensions.extension_ids,
        supported_groups: &extensions.supported_groups,
        ec_point_formats: &extensions.ec_point_formats,
        signature_algorithms: &extensions.signature_algorithms,
        sni: extensions.sni.as_deref(),
        alpn: &extensions.alpn,
    });

    Some(TlsInfo {
        sni: extensions.sni,
        alpn: extensions.alpn,
        version: Some(tls_version_string(highest_version)),
        ja3: fingerprint.ja3,
        ja3_hash: fingerprint.ja3_hash,
        ja3n: fingerprint.ja3n,
        ja3n_hash: fingerprint.ja3n_hash,
        ja4: fingerprint.ja4,
        ja4o: fingerprint.ja4o,
        ja4r: fingerprint.ja4r,
        ja4ro: fingerprint.ja4ro,
        cipher_count: cipher_suites
            .iter()
            .filter(|value| !is_grease_u16(**value))
            .count(),
        extension_count: extensions
            .extension_ids
            .iter()
            .filter(|value| !is_grease_u16(**value))
            .count(),
    })
}

fn parse_u16_values(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect()
}

const fn checked_end(start: usize, len: usize, limit: usize) -> Option<usize> {
    let Some(end) = start.checked_add(len) else {
        return None;
    };
    if end <= limit {
        Some(end)
    } else {
        None
    }
}

fn highest_tls_version(legacy_version: u16, supported_versions: &[u16]) -> u16 {
    supported_versions
        .iter()
        .copied()
        .filter(|version| !is_grease_u16(*version))
        .max()
        .unwrap_or(legacy_version)
}

const fn is_grease_u16(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

fn tls_version_string(version: u16) -> String {
    match version {
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        _ => format!("TLS 0x{version:04x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_handshake_detected() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01, 0x00, 0x05]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x01, 0x00, 0x05]));
    }

    #[test]
    fn tls_client_hello_with_sni_detected() {
        let result = analyze_tls_hello(&build_tls_client_hello("example.com"))
            .expect("should parse tls client hello");

        assert_eq!(result.sni.as_deref(), Some("example.com"));
        assert_eq!(result.version.as_deref(), Some("TLS 1.2"));
        assert!(result.alpn.is_empty());
        assert_eq!(result.cipher_count, 1);
        assert_eq!(result.extension_count, 1);
    }

    #[test]
    fn tls_client_hello_extracts_alpn_and_supported_version() {
        let result =
            analyze_tls_hello(&build_tls_client_hello_with_extra_extensions("example.com"))
                .expect("should parse tls client hello");

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
}
