//! # `mitm::transparent::upstream`
//!
//! **Purpose**: Sends transparent MITM requests to the preserved original destination.
//! **Public API**: module-private upstream forwarding helpers
//! **Dependencies**: `mitm`, `tokio-rustls`, `webpki-roots`, `http-mitm-proxy`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 138 / 150

use std::{net::SocketAddrV4, sync::Arc};

use bytes::Bytes;
use http_body_util::Full;
use http_mitm_proxy::{
    futures::TryFutureExt,
    hyper::{
        client,
        header::HOST,
        http::{HeaderValue, Uri},
        Request,
    },
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};

use super::{TransparentUpstream, UpstreamResponse};
use crate::{
    error::{EtwardenError, Result},
    output::diagnostic,
};

pub(super) async fn send_transparent_upstream(
    req: Request<Full<Bytes>>,
    upstream: &TransparentUpstream,
) -> Result<UpstreamResponse> {
    let uri = req.uri().clone();
    let stream = TcpStream::connect(std::net::SocketAddr::V4(SocketAddrV4::new(
        upstream.dest.ip,
        upstream.dest.port,
    )))
    .await
    .map_err(|e| EtwardenError::MitmProxy(format!("transparent upstream connect failed: {e}")))?;
    let _ = stream.set_nodelay(true);

    if upstream.scheme == "https" {
        send_transparent_tls_upstream(req, &uri, stream).await
    } else {
        send_transparent_http_upstream(req, stream).await
    }
}

async fn send_transparent_tls_upstream(
    req: Request<Full<Bytes>>,
    uri: &Uri,
    stream: TcpStream,
) -> Result<UpstreamResponse> {
    let host = uri.host().unwrap_or("localhost").to_owned();
    let server_name = host.clone().try_into().map_err(|_| {
        EtwardenError::MitmProxy(format!("invalid transparent upstream TLS host: {host}"))
    })?;
    let connector = transparent_tls_connector();
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent upstream TLS failed: {e}")))?;
    send_transparent_http1_request(req, TokioIo::new(stream), "TLS").await
}

async fn send_transparent_http_upstream(
    req: Request<Full<Bytes>>,
    stream: TcpStream,
) -> Result<UpstreamResponse> {
    send_transparent_http1_request(req, TokioIo::new(stream), "HTTP").await
}

async fn send_transparent_http1_request<I>(
    req: Request<Full<Bytes>>,
    io: TokioIo<I>,
    label: &'static str,
) -> Result<UpstreamResponse>
where
    TokioIo<I>: http_mitm_proxy::hyper::rt::Read
        + http_mitm_proxy::hyper::rt::Write
        + Unpin
        + Send
        + 'static,
{
    let (mut sender, conn) = client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await
        .map_err(|e| {
            EtwardenError::MitmProxy(format!(
                "transparent upstream {label} handshake failed: {e}"
            ))
        })?;
    tokio::spawn(conn.with_upgrades().map_err(move |err| {
        diagnostic::warn(format_args!(
            "MITM transparent upstream {label} closed: {err}"
        ));
    }));
    sender
        .send_request(strip_request_authority(req)?)
        .await
        .map(|res| (res, None))
        .map_err(|e| {
            EtwardenError::MitmProxy(format!("transparent upstream {label} request failed: {e}"))
        })
}

fn transparent_tls_connector() -> TlsConnector {
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    ))
}

pub(super) fn strip_request_authority<B>(mut req: Request<B>) -> Result<Request<B>> {
    if let Some(authority) = req.uri().authority().cloned() {
        let host = HeaderValue::from_str(authority.as_str()).map_err(|e| {
            EtwardenError::MitmProxy(format!("transparent upstream host header failed: {e}"))
        })?;
        req.headers_mut().insert(HOST, host);
    }
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    *req.uri_mut() = Uri::from_parts(parts).map_err(|e| {
        EtwardenError::MitmProxy(format!("transparent upstream URI strip failed: {e}"))
    })?;
    Ok(req)
}
