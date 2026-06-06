//! # `rules::replace`
//!
//! **Purpose**: Byte and file replacement rules for traffic-control payload rewriting.
//! **Public API**: `ReplaceAction`, `ReplaceRule`, `ReplaceOutcome`, `apply_first`,
//!   `apply_all`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 182 / 200

#[cfg(test)]
mod tests;

/// Replacement action performed when a source byte pattern matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceAction {
    /// Replace every matching source occurrence with `target` and keep processing.
    Bytes { target: Vec<u8> },
    /// Replace the whole payload with `body` and stop processing.
    File { body: Vec<u8> },
}

/// Byte-pattern replacement rule for URL/header/body payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceRule {
    /// Source byte pattern. Empty sources never match.
    pub source: Vec<u8>,
    /// Action applied after a match.
    pub action: ReplaceAction,
}

/// Result of applying replacement rules to a byte payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceOutcome {
    /// Rewritten payload.
    pub payload: Vec<u8>,
    /// Number of rules that matched.
    pub matched_rules: usize,
    /// Whether a `File` rule replaced the whole payload.
    pub file_replaced: bool,
}

impl ReplaceRule {
    /// Creates a byte-replacement rule.
    ///
    /// # Arguments
    /// * `source` — Pattern to search for. Empty patterns never match.
    /// * `target` — Replacement bytes for every occurrence.
    ///
    /// # Returns
    /// A `ReplaceRule` with `ReplaceAction::Bytes`.
    #[must_use]
    pub fn bytes(source: impl Into<Vec<u8>>, target: impl Into<Vec<u8>>) -> Self {
        Self {
            source: source.into(),
            action: ReplaceAction::Bytes {
                target: target.into(),
            },
        }
    }

    /// Creates a file-replacement rule.
    ///
    /// # Arguments
    /// * `source` — Pattern to search for. Empty patterns never match.
    /// * `body` — Full payload returned when the pattern matches.
    ///
    /// # Returns
    /// A `ReplaceRule` with `ReplaceAction::File`.
    #[must_use]
    pub fn file(source: impl Into<Vec<u8>>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            source: source.into(),
            action: ReplaceAction::File { body: body.into() },
        }
    }
}

/// Applies only the first matching rule.
///
/// # Arguments
/// * `payload` — Input payload to inspect.
/// * `rules` — Ordered replacement rules.
///
/// # Returns
/// Rewritten payload plus match metadata.
#[must_use]
pub fn apply_first(payload: &[u8], rules: &[ReplaceRule]) -> ReplaceOutcome {
    for rule in rules {
        let Some(outcome) = apply_rule(payload, rule) else {
            continue;
        };
        return outcome;
    }
    unchanged(payload)
}

/// Applies matching byte rules in order until exhausted or a file rule matches.
///
/// # Arguments
/// * `payload` — Input payload to inspect.
/// * `rules` — Ordered replacement rules.
///
/// # Returns
/// Rewritten payload plus match metadata.
#[must_use]
pub fn apply_all(payload: &[u8], rules: &[ReplaceRule]) -> ReplaceOutcome {
    let mut current = payload.to_vec();
    let mut matched_rules = 0;

    for rule in rules {
        let Some(outcome) = apply_rule(&current, rule) else {
            continue;
        };
        matched_rules += 1;
        current = outcome.payload;
        if outcome.file_replaced {
            return ReplaceOutcome {
                payload: current,
                matched_rules,
                file_replaced: true,
            };
        }
    }

    ReplaceOutcome {
        payload: current,
        matched_rules,
        file_replaced: false,
    }
}

fn apply_rule(payload: &[u8], rule: &ReplaceRule) -> Option<ReplaceOutcome> {
    if rule.source.is_empty() || !contains_bytes(payload, &rule.source) {
        return None;
    }

    match &rule.action {
        ReplaceAction::Bytes { target } => Some(ReplaceOutcome {
            payload: replace_all(payload, &rule.source, target),
            matched_rules: 1,
            file_replaced: false,
        }),
        ReplaceAction::File { body } => Some(ReplaceOutcome {
            payload: body.clone(),
            matched_rules: 1,
            file_replaced: true,
        }),
    }
}

fn unchanged(payload: &[u8]) -> ReplaceOutcome {
    ReplaceOutcome {
        payload: payload.to_vec(),
        matched_rules: 0,
        file_replaced: false,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn replace_all(payload: &[u8], source: &[u8], target: &[u8]) -> Vec<u8> {
    let mut rewritten = Vec::with_capacity(payload.len());
    let mut offset = 0;

    while offset < payload.len() {
        if payload[offset..].starts_with(source) {
            rewritten.extend_from_slice(target);
            offset += source.len();
        } else {
            rewritten.push(payload[offset]);
            offset += 1;
        }
    }

    rewritten
}
