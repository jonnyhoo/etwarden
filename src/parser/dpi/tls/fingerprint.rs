//! # `parser::dpi::tls::fingerprint`
//!
//! **Purpose**: Builds JA3/JA3N/JA4 passive TLS fingerprints from `ClientHello` fields.
//! **Public API**: module-private fingerprint builder
//! **Dependencies**: `md5`, `sha2`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 270 / 300

use std::{fmt::Write as _, net::IpAddr};

use md5::Md5;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub(super) struct FingerprintInput<'a> {
    pub(super) legacy_version: u16,
    pub(super) highest_version: u16,
    pub(super) cipher_suites: &'a [u16],
    pub(super) extensions: &'a [u16],
    pub(super) supported_groups: &'a [u16],
    pub(super) ec_point_formats: &'a [u8],
    pub(super) signature_algorithms: &'a [u16],
    pub(super) sni: Option<&'a str>,
    pub(super) alpn: &'a [String],
}

pub(super) struct TlsFingerprint {
    pub(super) ja3: String,
    pub(super) ja3_hash: String,
    pub(super) ja3n: String,
    pub(super) ja3n_hash: String,
    pub(super) ja4: String,
    pub(super) ja4o: String,
    pub(super) ja4r: String,
    pub(super) ja4ro: String,
}

pub(super) fn build_fingerprint(input: FingerprintInput<'_>) -> TlsFingerprint {
    let cipher_suites = filter_grease(input.cipher_suites);
    let extensions = filter_grease(input.extensions);
    let mut sorted_extensions = extensions.clone();
    sorted_extensions.sort_unstable();
    let supported_groups = filter_grease(input.supported_groups);
    let signature_algorithms = filter_grease(input.signature_algorithms);

    let classic_text = ja3_text(
        input.legacy_version,
        &cipher_suites,
        &extensions,
        &supported_groups,
        input.ec_point_formats,
    );
    let normalized_text = ja3_text(
        input.legacy_version,
        &cipher_suites,
        &sorted_extensions,
        &supported_groups,
        input.ec_point_formats,
    );

    let prefix = ja4_prefix(
        input.highest_version,
        input.sni,
        cipher_suites.len(),
        extensions.len(),
        input.alpn,
    );
    let original_fingerprint =
        ja4_hash(&prefix, &cipher_suites, &extensions, &signature_algorithms);
    let sorted_fingerprint = ja4_hash(
        &prefix,
        &sorted_u16(&cipher_suites),
        &sorted_extensions,
        &signature_algorithms,
    );
    let original_raw = ja4_raw(&prefix, &cipher_suites, &extensions, &signature_algorithms);
    let sorted_raw = ja4_raw(
        &prefix,
        &sorted_u16(&cipher_suites),
        &sorted_extensions,
        &signature_algorithms,
    );

    TlsFingerprint {
        ja3_hash: md5_hex(&classic_text),
        ja3n_hash: md5_hex(&normalized_text),
        ja3: classic_text,
        ja3n: normalized_text,
        ja4: sorted_fingerprint,
        ja4o: original_fingerprint,
        ja4r: sorted_raw,
        ja4ro: original_raw,
    }
}

fn ja3_text(
    legacy_version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    supported_groups: &[u16],
    ec_point_formats: &[u8],
) -> String {
    format!(
        "{},{},{},{},{}",
        legacy_version,
        decimal_join_u16(cipher_suites),
        decimal_join_u16(extensions),
        decimal_join_u16(supported_groups),
        decimal_join_u8(ec_point_formats),
    )
}

fn ja4_hash(
    prefix: &str,
    cipher_suites: &[u16],
    extensions: &[u16],
    signature_algorithms: &[u16],
) -> String {
    let cipher_hex = hex_join_u16(cipher_suites);
    let extension_hex = hex_join_u16(extensions);
    let signature_hex = hex_join_u16(signature_algorithms);
    format!(
        "{prefix}_{}_{}",
        sha256_12(&cipher_hex),
        sha256_12(&format!("{extension_hex}_{signature_hex}")),
    )
}

fn ja4_raw(
    prefix: &str,
    cipher_suites: &[u16],
    extensions: &[u16],
    signature_algorithms: &[u16],
) -> String {
    format!(
        "{prefix}_{}_{}_{}",
        hex_join_u16(cipher_suites),
        hex_join_u16(extensions),
        hex_join_u16(signature_algorithms),
    )
}

fn ja4_prefix(
    version: u16,
    sni: Option<&str>,
    cipher_count: usize,
    extension_count: usize,
    alpn: &[String],
) -> String {
    format!(
        "t{}{}{}{}{}",
        ja4_version(version),
        sni_marker(sni),
        count_two(cipher_count),
        count_two(extension_count),
        alpn_code(alpn),
    )
}

const fn ja4_version(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn sni_marker(sni: Option<&str>) -> &'static str {
    match sni {
        Some(value) if value.parse::<IpAddr>().is_err() => "d",
        _ => "i",
    }
}

fn alpn_code(alpn: &[String]) -> String {
    let Some(protocol) = alpn.first().map(String::as_str) else {
        return "00".into();
    };
    match protocol {
        "h2" => "h2".into(),
        "h3" => "h3".into(),
        "http/1.1" => "h1".into(),
        "http/1.0" => "h0".into(),
        _ => edge_alpn_code(protocol),
    }
}

fn edge_alpn_code(protocol: &str) -> String {
    let mut chars = protocol.chars().filter(char::is_ascii_alphanumeric);
    let Some(first) = chars.next() else {
        return "00".into();
    };
    let last = chars.next_back().unwrap_or(first);
    format!(
        "{}{}",
        first.to_ascii_lowercase(),
        last.to_ascii_lowercase()
    )
}

fn count_two(count: usize) -> String {
    format!("{:02}", count.min(99))
}

fn filter_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease_u16(*value))
        .collect()
}

fn sorted_u16(values: &[u16]) -> Vec<u16> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted
}

const fn is_grease_u16(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

fn decimal_join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn decimal_join_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn hex_join_u16(values: &[u16]) -> String {
    let mut output = String::with_capacity(values.len() * 4);
    for value in values {
        write!(&mut output, "{value:04x}").expect("writing to String cannot fail");
    }
    output
}

fn md5_hex(value: &str) -> String {
    format!("{:x}", Md5::digest(value.as_bytes()))
}

fn sha256_12(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
        .chars()
        .take(12)
        .collect()
}
