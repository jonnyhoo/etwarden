//! # `parser::dpi::tls`
//!
//! **Purpose**: Detects TLS `ClientHello` metadata, including SNI, ALPN, and version hints.
//! **Public API**: `TlsInfo`
//! **Dependencies**: `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 194 / 360

#[cfg(test)]
mod tests;

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
    let cipher_suites_data_start = cipher_suites_start + 2;
    let cipher_suites_end =
        checked_end(cipher_suites_data_start, cipher_suites_len, handshake_end)?;
    let cipher_suites = parse_u16_values(&payload[cipher_suites_data_start..cipher_suites_end]);

    let compression_start = cipher_suites_end;
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
