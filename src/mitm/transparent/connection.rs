//! # `mitm::transparent::connection`
//!
//! **Purpose**: Accepts transparent HTTP/TLS client sockets and injects original destination.
//! **Public API**: module-private connection spawner
//! **Dependencies**: `mitm`, `transparent::{cert, uri}`, `tokio`, `http-mitm-proxy`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 133 / 140

use std::{net::SocketAddr, sync::Arc};

use http_body_util::Full;
use http_mitm_proxy::{
    hyper::{body::Incoming, server, service::service_fn, Request, Response},
    RemoteAddr,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, LazyConfigAcceptor};

use super::{cert::server_config_for_host, uri::transparent_uri, TransparentUpstream};
use crate::{
    error::{EtwardenError, Result},
    mitm::{handle_request, ProxyState},
    output::diagnostic,
};

pub(in crate::mitm) fn spawn_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    state: Arc<ProxyState>,
    upstream: TransparentUpstream,
) {
    tokio::spawn(async move {
        if let Err(err) = handle_connection(stream, remote_addr, state, upstream).await {
            diagnostic::warn(format_args!("MITM transparent connection closed: {err}"));
        }
    });
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    state: Arc<ProxyState>,
    upstream: TransparentUpstream,
) -> Result<()> {
    if upstream.scheme == "https" {
        handle_tls_connection(stream, remote_addr, state, upstream).await
    } else {
        handle_http_connection(stream, remote_addr, state, upstream).await
    }
}

async fn handle_http_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    state: Arc<ProxyState>,
    upstream: TransparentUpstream,
) -> Result<()> {
    let service = service_fn(move |mut req| {
        req.extensions_mut().insert(RemoteAddr(remote_addr));
        inject_origin(req, upstream.clone(), Arc::clone(&state))
    });
    server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent HTTP connection failed: {e}")))
}

async fn handle_tls_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    state: Arc<ProxyState>,
    upstream: TransparentUpstream,
) -> Result<()> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start = acceptor.await.map_err(|e| {
        EtwardenError::MitmProxy(format!(
            "transparent TLS accept failed before ClientHello: {e}"
        ))
    })?;
    let server_name = start
        .client_hello()
        .server_name()
        .map_or_else(|| upstream.dest.ip.to_string(), str::to_owned);
    let server_config = Arc::new(server_config_for_host(&state.issuer, server_name)?);
    let upstream = TransparentUpstream {
        host_hint: Some(
            start
                .client_hello()
                .server_name()
                .map_or_else(|| upstream.dest.ip.to_string(), str::to_owned),
        ),
        ..upstream
    };
    let client = start
        .into_stream(server_config)
        .await
        .map_err(|e| EtwardenError::MitmProxy(format!("transparent TLS accept failed: {e}")))?;

    let service = service_fn(move |mut req| {
        req.extensions_mut().insert(RemoteAddr(remote_addr));
        inject_origin(req, upstream.clone(), Arc::clone(&state))
    });
    let res = if client.get_ref().1.alpn_protocol() == Some(b"h2") {
        server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(client), service)
            .await
    } else {
        server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(client), service)
            .with_upgrades()
            .await
    };
    res.map_err(|e| EtwardenError::MitmProxy(format!("transparent TLS connection failed: {e}")))
}

async fn inject_origin(
    mut req: Request<Incoming>,
    upstream: TransparentUpstream,
    state: Arc<ProxyState>,
) -> Result<Response<Full<bytes::Bytes>>> {
    let uri = transparent_uri(&req, &upstream)?;
    req.extensions_mut().insert(upstream);
    *req.uri_mut() = uri;
    handle_request(req, state).await
}
