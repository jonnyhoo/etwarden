//! # `parser::dpi::tls`
//!
//! **Purpose**: Detects TLS `ClientHello` metadata, including SNI.
//! **Public API**: `TlsInfo`
//! **Dependencies**: `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 170 / 230

use serde::Serialize;

/// TLS `ClientHello` information.
#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    /// Server Name Indication hostname extracted from `ClientHello`.
    pub sni: Option<String>,
    /// TLS version string (e.g. "TLS 1.3").
    pub version: Option<String>,
}

/// Check if the payload starts with a TLS record header (content type 22 = Handshake).
pub(super) fn is_tls_handshake(payload: &[u8]) -> bool {
    payload.len() >= 5
        && payload[0] == 0x16
        && payload[1] == 0x03
        && (0x01..=0x03).contains(&payload[2])
}

/// Parse TLS `ClientHello` to extract SNI and version.
pub(super) fn analyze_tls_hello(payload: &[u8]) -> Option<TlsInfo> {
    if payload.len() < 43 || !is_tls_handshake(payload) {
        return None;
    }

    let record_version = u16::from_be_bytes([payload[1], payload[2]]);
    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    let record_end = checked_end(5, record_len, payload.len())?;

    if payload[5] != 0x01 {
        return None;
    }

    let handshake_len =
        (usize::from(payload[6]) << 16) | (usize::from(payload[7]) << 8) | usize::from(payload[8]);
    let handshake_end = checked_end(9, handshake_len, record_end)?;

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
    let mut offset = extensions_start + 2;

    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([
            payload[offset + 2],
            payload[offset + 3],
        ]));
        let ext_data_start = offset + 4;
        let ext_data_end = checked_end(ext_data_start, ext_len, extensions_end)?;

        if ext_type == 0x0000 {
            return Some(TlsInfo {
                sni: extract_sni_from_extension(payload, ext_data_start, ext_len),
                version: Some(tls_version_string(record_version)),
            });
        }

        offset = ext_data_end;
    }

    if offset != extensions_end {
        return None;
    }

    Some(TlsInfo {
        sni: None,
        version: Some(tls_version_string(record_version)),
    })
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

fn extract_sni_from_extension(
    payload: &[u8],
    ext_data_start: usize,
    ext_len: usize,
) -> Option<String> {
    let ext_end = checked_end(ext_data_start, ext_len, payload.len())?;
    let list_len_end = checked_end(ext_data_start, 2, ext_end)?;
    let list_len = usize::from(u16::from_be_bytes([
        payload[ext_data_start],
        payload[ext_data_start + 1],
    ]));
    let list_end = checked_end(list_len_end, list_len, ext_end)?;
    if list_end != ext_end {
        return None;
    }

    let entry_start = list_len_end;
    checked_end(entry_start, 3, list_end)?;
    if payload[entry_start] != 0 {
        return None;
    }

    let entry_len = usize::from(u16::from_be_bytes([
        payload[entry_start + 1],
        payload[entry_start + 2],
    ]));
    let hostname_start = entry_start + 3;
    let hostname_end = checked_end(hostname_start, entry_len, list_end)?;
    let hostname = &payload[hostname_start..hostname_end];
    if hostname.is_empty() {
        return None;
    }

    std::str::from_utf8(hostname).ok().map(str::to_string)
}

fn tls_version_string(version: u16) -> String {
    match version {
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2/1.3".to_string(),
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
        assert_eq!(result.version.as_deref(), Some("TLS 1.2/1.3"));
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

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(
            &u16::try_from(sni.len())
                .expect("sni length fits")
                .to_be_bytes(),
        );
        extensions.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("extensions length fits")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

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
