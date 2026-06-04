//! # `tracker::endpoint`
//!
//! **Purpose**: Classifies tracked connection remote endpoint scopes.
//! **Public API**: module-private scope helper
//! **Dependencies**: `classify`, `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 35 / 80

use crate::{classify, parser::types::FiveTuple};

/// Classify the remote endpoint IP scope.
pub(super) fn classify_remote(tuple: &FiveTuple) -> Option<&'static str> {
    let dst_ip: std::net::IpAddr = tuple.dst_ip.parse().ok()?;
    let src_ip: std::net::IpAddr = tuple.src_ip.parse().ok()?;
    let remote = if is_local_ip(&dst_ip) {
        &src_ip
    } else {
        &dst_ip
    };

    Some(classify::classify(*remote).label())
}

fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    matches!(
        classify::classify(*ip),
        classify::Scope::Loopback | classify::Scope::Private
    )
}
