//! # `rules::config::replace`
//!
//! **Purpose**: Replacement-rule config shapes and decoding.
//! **Public API**: `ReplaceRuleConfig`, `DecodedReplaceRuleConfig`, `ReplacementRuleKind`
//! **Dependencies**: `rules::config::value`, `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 65 / 120

use serde::Deserialize;

use super::value::{decode_value, RuleConfigError, RuleValueEncoding};

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
