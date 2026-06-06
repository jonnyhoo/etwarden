//! # `rules::hosts`
//!
//! **Purpose**: Host-rewrite rules for URL traffic-control targets.
//! **Public API**: `HostsRewrite`, `HostsRule`, `HostsRuleError`, `rewrite_first_url`
//! **Dependencies**: `regex`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 173 / 200

#[cfg(test)]
mod tests;

use std::ops::Range;

use regex::{Regex, RegexBuilder};

/// Compiled host rewrite rule.
#[derive(Debug, Clone)]
pub struct HostsRule {
    /// Case-insensitive regex applied to the URL host.
    pub pattern: Regex,
    /// Replacement string for the matched host. Regex captures are supported.
    pub target: String,
}

/// Result of applying host rewrite rules to one URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsRewrite {
    /// URL after host rewriting, or original URL when no rule matched.
    pub url: String,
    /// Index of the first matching rule.
    pub matched_rule: Option<usize>,
}

/// Hosts rule construction error.
#[derive(Debug, thiserror::Error)]
pub enum HostsRuleError {
    /// Regex pattern failed to compile.
    #[error("invalid hosts pattern: {0}")]
    RegexCompile(#[from] regex::Error),
}

impl HostsRule {
    /// Builds a host rewrite rule.
    ///
    /// # Arguments
    /// * `pattern` — Case-insensitive regex matched against the URL host only.
    /// * `target` — Replacement text for the matched host.
    ///
    /// # Returns
    /// A compiled `HostsRule`.
    ///
    /// # Errors
    /// Returns `HostsRuleError` when `pattern` cannot compile.
    pub fn new(pattern: &str, target: impl Into<String>) -> Result<Self, HostsRuleError> {
        let mut builder = RegexBuilder::new(pattern);
        Ok(Self {
            pattern: builder.case_insensitive(true).build()?,
            target: target.into(),
        })
    }

    /// Checks whether this rule matches `host`.
    ///
    /// # Arguments
    /// * `host` — URL host without port or IPv6 brackets.
    ///
    /// # Returns
    /// `true` when `pattern` matches `host`.
    #[must_use]
    pub fn matches_host(&self, host: &str) -> bool {
        self.pattern.is_match(host)
    }

    /// Rewrites a host with this rule.
    ///
    /// # Arguments
    /// * `host` — URL host without port or IPv6 brackets.
    ///
    /// # Returns
    /// Rewritten host when the rule matches; otherwise `None`.
    #[must_use]
    pub fn rewrite_host(&self, host: &str) -> Option<String> {
        self.matches_host(host).then(|| {
            self.pattern
                .replace(host, self.target.as_str())
                .into_owned()
        })
    }
}

/// Applies the first matching hosts rule to a URL.
///
/// # Arguments
/// * `url` — Absolute URL or host-first URL string.
/// * `rules` — Ordered hosts rules.
///
/// # Returns
/// Rewritten URL plus the index of the matched rule, or the original URL when no rule matched.
#[must_use]
pub fn rewrite_first_url(url: &str, rules: &[HostsRule]) -> HostsRewrite {
    let Some(host_range) = host_range(url) else {
        return unchanged(url);
    };
    let host = &url[host_range.clone()];

    for (rule_index, rule) in rules.iter().enumerate() {
        let Some(rewritten_host) = rule.rewrite_host(host) else {
            continue;
        };
        return HostsRewrite {
            url: rewrite_range(url, host_range, &rewritten_host),
            matched_rule: Some(rule_index),
        };
    }

    unchanged(url)
}

fn unchanged(url: &str) -> HostsRewrite {
    HostsRewrite {
        url: url.to_owned(),
        matched_rule: None,
    }
}

fn rewrite_range(url: &str, range: Range<usize>, replacement: &str) -> String {
    let mut rewritten = String::with_capacity(url.len() - range.len() + replacement.len());
    rewritten.push_str(&url[..range.start]);
    rewritten.push_str(replacement);
    rewritten.push_str(&url[range.end..]);
    rewritten
}

fn host_range(url: &str) -> Option<Range<usize>> {
    let authority_start = url.find("://").map_or(0, |scheme_end| scheme_end + 3);
    let authority_tail = &url[authority_start..];
    let authority_end = authority_start
        + authority_tail
            .find(['/', '?', '#'])
            .unwrap_or(authority_tail.len());
    let authority = &url[authority_start..authority_end];
    if authority.is_empty() {
        return None;
    }

    let host_start = authority
        .rfind('@')
        .map_or(authority_start, |offset| authority_start + offset + 1);
    bracketed_or_plain_host_range(url, host_start, authority_end)
}

fn bracketed_or_plain_host_range(
    url: &str,
    host_start: usize,
    authority_end: usize,
) -> Option<Range<usize>> {
    if url
        .as_bytes()
        .get(host_start)
        .is_some_and(|byte| *byte == b'[')
    {
        let inside_start = host_start + 1;
        let close = inside_start + url[inside_start..authority_end].find(']')?;
        return (inside_start < close).then_some(inside_start..close);
    }

    let host = &url[host_start..authority_end];
    let host_end = host
        .find(':')
        .map_or(authority_end, |offset| host_start + offset);
    (host_start < host_end).then_some(host_start..host_end)
}
