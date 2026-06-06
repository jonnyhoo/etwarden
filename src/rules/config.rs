//! # `rules::config`
//!
//! **Purpose**: Typed traffic-control rules config and value decoding.
//! **Public API**: `RulesConfig`, `ReplaceRuleConfig`, `DecodedReplaceRuleConfig`,
//!   `ReplacementRuleKind`, `RuleValueEncoding`, `RuleConfigError`
//! **Dependencies**: `base64`, `serde`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 163 / 200

#[cfg(test)]
mod tests;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

/// Top-level traffic-control rules config.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    /// Ordered replacement rules.
    #[serde(default)]
    pub replace_rules: Vec<ReplaceRuleConfig>,
}

/// Config shape for one replacement rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReplaceRuleConfig {
    /// Replacement behavior.
    #[serde(rename = "type")]
    pub rule_type: ReplacementRuleKind,
    /// Source pattern to match, encoded using `encoding`.
    pub source: String,
    /// Target bytes/body, encoded using `encoding`.
    pub target: String,
    /// Encoding used for `source` and `target`.
    #[serde(default)]
    pub encoding: RuleValueEncoding,
}

/// Decoded replacement rule config with raw byte values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReplaceRuleConfig {
    /// Replacement behavior.
    pub rule_type: ReplacementRuleKind,
    /// Decoded source byte pattern.
    pub source: Vec<u8>,
    /// Decoded target bytes or file body.
    pub target: Vec<u8>,
}

/// Replacement rule behavior from config.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum ReplacementRuleKind {
    /// Replace matching bytes in the payload.
    Bytes,
    /// Replace the whole payload with configured bytes.
    File,
}

/// Encoding for byte values in rule config.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub enum RuleValueEncoding {
    /// UTF-8 string bytes.
    #[serde(rename = "UTF8", alias = "utf8", alias = "Utf8")]
    #[default]
    Utf8,
    /// Hexadecimal bytes. ASCII whitespace is ignored.
    #[serde(rename = "HEX", alias = "hex", alias = "Hex")]
    Hex,
    /// Base64 bytes.
    #[serde(rename = "BASE64", alias = "Base64", alias = "base64")]
    Base64,
}

/// Rules config decoding error.
#[derive(Debug, thiserror::Error)]
pub enum RuleConfigError {
    /// Hex input contained an odd number of digits.
    #[error("hex value must contain an even number of digits, got {digits}")]
    InvalidHexLength { digits: usize },
    /// Hex input contained a non-hex digit.
    #[error("invalid hex digit '{value}' at index {index}")]
    InvalidHexDigit { index: usize, value: char },
    /// Base64 decoding failed.
    #[error("invalid base64 value: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

impl RulesConfig {
    /// Decodes configured replacement rules.
    ///
    /// # Returns
    /// Ordered decoded replacement rule configs.
    ///
    /// # Errors
    /// Returns `RuleConfigError` if any encoded `source` or `target` value is invalid.
    pub fn decode_replace_rules(&self) -> Result<Vec<DecodedReplaceRuleConfig>, RuleConfigError> {
        self.replace_rules
            .iter()
            .map(ReplaceRuleConfig::decode)
            .collect()
    }
}

impl ReplaceRuleConfig {
    /// Decodes one config replacement rule.
    ///
    /// # Returns
    /// A decoded replacement rule config.
    ///
    /// # Errors
    /// Returns `RuleConfigError` when the configured value encoding is invalid.
    pub fn decode(&self) -> Result<DecodedReplaceRuleConfig, RuleConfigError> {
        Ok(DecodedReplaceRuleConfig {
            rule_type: self.rule_type,
            source: decode_value(&self.source, self.encoding)?,
            target: decode_value(&self.target, self.encoding)?,
        })
    }
}

fn decode_value(value: &str, encoding: RuleValueEncoding) -> Result<Vec<u8>, RuleConfigError> {
    match encoding {
        RuleValueEncoding::Utf8 => Ok(value.as_bytes().to_vec()),
        RuleValueEncoding::Hex => decode_hex(value),
        RuleValueEncoding::Base64 => Ok(STANDARD.decode(value)?),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RuleConfigError> {
    let digits: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.len() & 1 == 1 {
        return Err(RuleConfigError::InvalidHexLength {
            digits: digits.len(),
        });
    }

    digits
        .chunks_exact(2)
        .enumerate()
        .map(|(pair_index, pair)| {
            let high = hex_digit(pair[0], pair_index * 2)?;
            let low = hex_digit(pair[1], pair_index * 2 + 1)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8, index: usize) -> Result<u8, RuleConfigError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RuleConfigError::InvalidHexDigit {
            index,
            value: char::from(byte),
        }),
    }
}
