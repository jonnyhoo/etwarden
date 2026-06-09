//! # `mitm::transparent::uri`
//!
//! **Purpose**: Rebuilds absolute request URIs for transparently redirected sockets.
//! **Public API**: module-private URI helpers
//! **Dependencies**: `mitm`, `http-mitm-proxy`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 78 / 100

use http_mitm_proxy::hyper::{
    body::Incoming,
    header::HOST,
    http::{
        uri::{Authority, Scheme},
        HeaderMap, Uri,
    },
    Request,
};

use super::TransparentUpstream;
use crate::error::{EtwardenError, Result};

pub(super) const fn scheme_for_port(port: u16) -> &'static str {
    if port == 443 {
        "https"
    } else {
        "http"
    }
}

pub(super) fn transparent_uri(
    req: &Request<Incoming>,
    upstream: &TransparentUpstream,
) -> Result<Uri> {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = Some(if upstream.scheme == "https" {
        Scheme::HTTPS
    } else {
        Scheme::HTTP
    });
    parts.authority = Some(transparent_authority(req.uri(), req.headers(), upstream)?);
    Uri::from_parts(parts)
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent URI build failed: {e}")))
}

pub(super) fn transparent_authority(
    uri: &Uri,
    headers: &HeaderMap,
    upstream: &TransparentUpstream,
) -> Result<Authority> {
    let host = uri
        .authority()
        .map(|authority| authority.host().to_owned())
        .or_else(|| {
            super::super::header_value(headers, HOST)
                .and_then(|value| value.parse::<Authority>().ok())
                .map(|authority| authority.host().to_owned())
        })
        .or_else(|| upstream.host_hint.clone())
        .unwrap_or_else(|| upstream.dest.ip.to_string());
    let value = if upstream.dest.port == default_port_for_scheme(upstream.scheme) {
        host
    } else {
        format!("{host}:{}", upstream.dest.port)
    };
    value
        .parse()
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent authority build failed: {e}")))
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}
