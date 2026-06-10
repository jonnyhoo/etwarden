//! # `mitm::transparent`
//!
//! **Purpose**: Routes transparent WinDivert sockets by sniffed protocol.
//! **Public API**: module-private transparent redirect helpers
//! **Dependencies**: `mitm`, `transparent::{connection, upstream, uri}`, `divert`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 86 / 110

mod cert;
mod connection;
#[cfg(test)]
mod map_tests;
mod protocol;
mod tcp;
#[cfg(test)]
mod tests;
mod upstream;
mod uri;

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
pub(super) use connection::spawn_connection;
use http_body_util::Full;
use http_mitm_proxy::hyper::{body::Incoming, Request, Response};
use protocol::TransparentProtocol;

use super::ProxyState;
use crate::{
    divert::{OriginalDest, RedirectMap},
    error::{EtwardenError, Result},
};

type Upgraded = http_mitm_proxy::default_client::Upgraded;
type HyperError = http_mitm_proxy::hyper::Error;
pub(super) type UpgradeTask = tokio::task::JoinHandle<std::result::Result<Upgraded, HyperError>>;
pub(super) type UpstreamResponse = (Response<Incoming>, Option<UpgradeTask>);

#[derive(Clone)]
pub(super) struct TransparentUpstream {
    pub(super) dest: OriginalDest,
    protocol: TransparentProtocol,
    host_hint: Option<String>,
}

impl TransparentUpstream {
    const fn with_protocol(mut self, protocol: TransparentProtocol) -> Self {
        self.protocol = protocol;
        self
    }
}

pub(super) fn upstream_from_map(
    state: &ProxyState,
    remote_addr: SocketAddr,
) -> Option<TransparentUpstream> {
    let dest = redirect_dest_from_peer(state.redirect_map.as_ref()?, remote_addr)?;
    Some(TransparentUpstream {
        protocol: TransparentProtocol::Detect,
        dest,
        host_hint: None,
    })
}

fn redirect_dest_from_peer(map: &RedirectMap, remote_addr: SocketAddr) -> Option<OriginalDest> {
    let dest = map.get(remote_addr.port())?;
    (remote_addr.ip() == IpAddr::V4(dest.ip)).then_some(dest)
}

pub(super) async fn send_upstream_request(
    state: &ProxyState,
    req: Request<Full<Bytes>>,
    upstream: Option<&TransparentUpstream>,
) -> Result<UpstreamResponse> {
    if let Some(target) = upstream {
        upstream::send_transparent_upstream(req, target).await
    } else {
        state
            .client
            .send_request(req)
            .await
            .map_err(|e| EtwardenError::MitmProxy(format!("MITM upstream request failed: {e}")))
    }
}
