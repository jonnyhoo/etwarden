//! # `mitm`
//!
//! **Purpose**: Active HTTPS MITM proxy that emits decrypted HTTP metadata into NDJSON flow.
//! **Public API**: `MitmCaptureConfig`, `MitmProxyConfig`, `MitmProxyHandle`, `start_mitm_proxy`
//! **Dependencies**: `http-mitm-proxy`, `tokio`, `rcgen`, `parser`, `pcap`
//! **Platform**: `windows-only`
//! **Privilege**: `optional-user-proxy-write`
//! **Line budget**: 300 / 340

mod body;
mod ca;
mod pid;
mod system_proxy;

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use bytes::Bytes;
pub use ca::CertificateAuthorityConfig;
use http_body_util::{BodyExt, Full, Limited};
use http_mitm_proxy::{
    hyper::{
        body::{Body, Incoming},
        header::{HeaderName, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST},
        http::{request, response, HeaderMap, Uri},
        server,
        service::{service_fn, HttpService},
        Request, Response, Version,
    },
    moka::sync::Cache,
    DefaultClient, MitmProxy, RemoteAddr,
};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, sync::oneshot};

use self::{
    body::capture_body, ca::load_or_generate_issuer, pid::resolve_proxy_pid,
    system_proxy::SystemProxyGuard,
};
use crate::{
    error::{EtwardenError, Result},
    output::diagnostic,
    parser::{types::NetEvent, ParserRegistry},
    pcap::correlator::Correlator,
};

const CERT_CACHE_SIZE: u64 = 128;

type RootIssuer = Arc<rcgen::Issuer<'static, rcgen::KeyPair>>;
type Proxy = MitmProxy<RootIssuer>;

/// User-facing MITM proxy settings from CLI/capture config.
#[derive(Debug, Clone)]
pub struct MitmCaptureConfig {
    pub listen_addr: SocketAddr,
    pub ca: CertificateAuthorityConfig,
    pub body_limit: usize,
    pub max_body_bytes: usize,
    pub enable_system_proxy: bool,
}

/// Runtime MITM proxy config wired to active capture state.
pub struct MitmProxyConfig {
    pub capture: MitmCaptureConfig,
    pub target_pid: u32,
    pub registry: Arc<ParserRegistry>,
    pub correlator: Arc<Correlator>,
    pub stop_signal: Option<Arc<AtomicBool>>,
}

/// Running MITM proxy thread handle.
pub struct MitmProxyHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

/// Starts the active HTTPS MITM proxy.
///
/// # Errors
/// Returns [`EtwardenError::MitmProxy`] if the proxy cannot bind, initialize TLS, or set system proxy.
pub fn start_mitm_proxy(config: MitmProxyConfig) -> Result<MitmProxyHandle> {
    validate_config(&config.capture)?;

    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let thread = thread::Builder::new()
        .name("etwarden-mitm-proxy".into())
        .spawn(move || proxy_thread(config, stop_rx, &ready_tx))
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to spawn MITM proxy thread: {e}")))?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(MitmProxyHandle {
            stop_tx: Some(stop_tx),
            thread: Some(thread),
        }),
        Ok(Err(message)) => {
            join_after_start_failure(thread)?;
            Err(EtwardenError::MitmProxy(message))
        }
        Err(err) => {
            join_after_start_failure(thread)?;
            Err(EtwardenError::MitmProxy(format!(
                "MITM proxy thread exited before readiness: {err}"
            )))
        }
    }
}

impl MitmProxyHandle {
    /// Stops the proxy and restores system proxy settings if they were changed.
    ///
    /// # Errors
    /// Returns [`EtwardenError::MitmProxy`] when the proxy thread cannot stop cleanly.
    pub fn stop(mut self) -> Result<()> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<()> {
        if let Some(stop_tx) = self.stop_tx.take() {
            if stop_tx.send(()).is_err() {
                diagnostic::warn(format_args!(
                    "MITM proxy stop signal receiver already closed"
                ));
            }
        }
        if let Some(thread) = self.thread.take() {
            return thread
                .join()
                .map_err(|_| EtwardenError::MitmProxy("MITM proxy thread panicked".into()))?;
        }
        Ok(())
    }
}

impl Drop for MitmProxyHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_inner() {
            diagnostic::warn(format_args!("{err}"));
        }
    }
}

struct ProxyState {
    target_pid: u32,
    listen_addr: SocketAddr,
    body_limit: usize,
    max_body_bytes: usize,
    client: DefaultClient,
    registry: Arc<ParserRegistry>,
    correlator: Arc<Correlator>,
}

fn validate_config(config: &MitmCaptureConfig) -> Result<()> {
    if config.body_limit > config.max_body_bytes {
        return Err(EtwardenError::MitmProxy(format!(
            "MITM body limit {} exceeds max body bytes {}",
            config.body_limit, config.max_body_bytes
        )));
    }
    if config.max_body_bytes == 0 {
        return Err(EtwardenError::MitmProxy(
            "MITM max body bytes must be greater than zero".into(),
        ));
    }
    Ok(())
}

fn proxy_thread(
    config: MitmProxyConfig,
    stop_rx: oneshot::Receiver<()>,
    ready_tx: &mpsc::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    install_rustls_provider();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to start Tokio runtime: {e}")))?;

    let result = runtime.block_on(run_proxy(config, stop_rx, ready_tx));
    if let Err(err) = &result {
        let _ignored = ready_tx.send(Err(err.to_string()));
    }
    result
}

fn install_rustls_provider() {
    if tokio_rustls::rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ignored = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }
}

async fn run_proxy(
    config: MitmProxyConfig,
    stop_rx: oneshot::Receiver<()>,
    ready_tx: &mpsc::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let issuer = load_or_generate_issuer(&config.capture.ca)?;
    let listener = TcpListener::bind(config.capture.listen_addr)
        .await
        .map_err(|e| {
            EtwardenError::MitmProxy(format!(
                "failed to bind MITM proxy {}: {e}",
                config.capture.listen_addr
            ))
        })?;
    let listen_addr = listener
        .local_addr()
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to read MITM proxy addr: {e}")))?;
    let client = DefaultClient::try_new()
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to initialize MITM client: {e}")))?;
    let state = Arc::new(ProxyState {
        target_pid: config.target_pid,
        listen_addr,
        body_limit: config.capture.body_limit,
        max_body_bytes: config.capture.max_body_bytes,
        client,
        registry: config.registry,
        correlator: config.correlator,
    });
    let target_proxy = Arc::new(MitmProxy::new(
        Some(issuer),
        Some(Cache::new(CERT_CACHE_SIZE)),
    ));
    let passthrough_proxy: Arc<Proxy> = Arc::new(MitmProxy::new(None, None));
    let mut system_proxy = if config.capture.enable_system_proxy {
        Some(SystemProxyGuard::enable(listen_addr)?)
    } else {
        None
    };

    let _ignored = ready_tx.send(Ok(()));
    diagnostic::warn(format_args!("MITM proxy listening on {listen_addr}"));

    let stop = stop_signal(config.stop_signal);
    tokio::pin!(stop);
    tokio::pin!(stop_rx);

    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            () = &mut stop => break,
            accepted = listener.accept() => {
                let (stream, remote_addr) = match accepted {
                    Ok(conn) => conn,
                    Err(err) => {
                        diagnostic::warn(format_args!("MITM proxy accept failed: {err}"));
                        continue;
                    }
                };
                if is_target_client(&state, remote_addr) {
                    let proxy = Arc::clone(&target_proxy);
                    let state = Arc::clone(&state);
                    let service = service_fn(move |req| handle_request(req, Arc::clone(&state)));
                    spawn_proxy_connection(stream, remote_addr, proxy, service);
                } else {
                    let proxy = Arc::clone(&passthrough_proxy);
                    let state = Arc::clone(&state);
                    let service = service_fn(move |req| handle_passthrough(req, Arc::clone(&state)));
                    spawn_proxy_connection(stream, remote_addr, proxy, service);
                }
            }
        }
    }

    if let Some(guard) = system_proxy.as_mut() {
        guard.restore()?;
    }
    Ok(())
}

fn spawn_proxy_connection<S>(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    proxy: Arc<Proxy>,
    service: S,
) where
    S: HttpService<Incoming> + Clone + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::ResBody: Body + Send + Sync + 'static,
    <S::ResBody as Body>::Data: Send,
    <S::ResBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::Future: Send,
{
    tokio::spawn(async move {
        let proxy_service = service_fn(move |mut req| {
            req.extensions_mut().insert(RemoteAddr(remote_addr));
            MitmProxy::wrap_service(Arc::clone(&proxy), service.clone()).call(req)
        });
        if let Err(err) = server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(stream), proxy_service)
            .with_upgrades()
            .await
        {
            diagnostic::warn(format_args!("MITM proxy connection closed: {err}"));
        }
    });
}

fn is_target_client(state: &ProxyState, remote_addr: SocketAddr) -> bool {
    resolve_proxy_pid(&state.correlator, remote_addr, state.listen_addr)
        .is_some_and(|pid| pid == state.target_pid)
}

async fn stop_signal(signal: Option<Arc<AtomicBool>>) {
    let Some(signal) = signal else {
        std::future::pending::<()>().await;
        return;
    };
    while !signal.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn handle_passthrough(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Incoming>> {
    state
        .client
        .send_request(req)
        .await
        .map(|(res, _upgrade)| res)
        .map_err(|e| EtwardenError::MitmProxy(format!("MITM passthrough request failed: {e}")))
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>> {
    let remote_addr = req.extensions().get::<RemoteAddr>().map(|addr| addr.0);
    let pid = remote_addr
        .and_then(|addr| resolve_proxy_pid(&state.correlator, addr, state.listen_addr))
        .filter(|pid| *pid == state.target_pid);

    let (client_request_parts, client_request_stream) = req.into_parts();
    let upstream_uri = client_request_parts.uri.clone();
    let captured_request_body =
        collect_body(client_request_stream, state.max_body_bytes, "request").await?;
    if let (Some(pid), Some(remote_addr)) = (pid, remote_addr) {
        state.registry.push_event(request_event(
            pid,
            remote_addr,
            &client_request_parts,
            &captured_request_body,
            state.body_limit,
        )?);
    }

    let upstream_req = Request::from_parts(client_request_parts, Full::new(captured_request_body));
    let (upstream_response, _upgrade) = state
        .client
        .send_request(upstream_req)
        .await
        .map_err(|e| EtwardenError::MitmProxy(format!("MITM upstream request failed: {e}")))?;
    let (server_response_parts, server_response_stream) = upstream_response.into_parts();
    let captured_response_body =
        collect_body(server_response_stream, state.max_body_bytes, "response").await?;
    if let (Some(pid), Some(remote_addr)) = (pid, remote_addr) {
        state.registry.push_event(response_event(
            pid,
            remote_addr,
            &upstream_uri,
            &server_response_parts,
            &captured_response_body,
            state.body_limit,
        )?);
    }

    Ok(Response::from_parts(
        server_response_parts,
        Full::new(captured_response_body),
    ))
}

async fn collect_body<B>(body: B, limit: usize, label: &str) -> Result<Bytes>
where
    B: Body<Data = Bytes>,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    Limited::new(body, limit)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|e| EtwardenError::MitmProxy(format!("failed to collect MITM {label} body: {e}")))
}

fn request_event(
    pid: u32,
    remote_addr: SocketAddr,
    parts: &request::Parts,
    body: &[u8],
    body_limit: usize,
) -> Result<NetEvent> {
    let captured = capture_body(
        header_value(&parts.headers, CONTENT_ENCODING),
        content_length(&parts.headers),
        body,
        body_limit,
    )?;
    Ok(NetEvent::DecryptedHttpRequest {
        timestamp: chrono::Utc::now(),
        pid,
        src: remote_addr.to_string(),
        dst: request_dst(&parts.uri),
        method: parts.method.as_str().to_owned(),
        path: request_path(&parts.uri),
        host: host_value(&parts.uri, &parts.headers),
        version: version_string(parts.version),
        content_type: header_string(&parts.headers, CONTENT_TYPE),
        content_length: captured.content_length,
        content_encoding: captured.content_encoding,
        decoded: captured.decoded,
        body_base64: captured.body_base64,
        body_truncated: captured.body_truncated,
    })
}

fn response_event(
    pid: u32,
    remote_addr: SocketAddr,
    request_uri: &Uri,
    parts: &response::Parts,
    body: &[u8],
    body_limit: usize,
) -> Result<NetEvent> {
    let captured = capture_body(
        header_value(&parts.headers, CONTENT_ENCODING),
        content_length(&parts.headers),
        body,
        body_limit,
    )?;
    Ok(NetEvent::DecryptedHttpResponse {
        timestamp: chrono::Utc::now(),
        pid,
        src: request_dst(request_uri),
        dst: remote_addr.to_string(),
        status_line: status_line(parts.version, parts.status),
        host: request_uri.host().map(str::to_owned),
        version: version_string(parts.version),
        status_code: parts.status.as_u16(),
        content_type: header_string(&parts.headers, CONTENT_TYPE),
        content_length: captured.content_length,
        content_encoding: captured.content_encoding,
        decoded: captured.decoded,
        body_base64: captured.body_base64,
        body_truncated: captured.body_truncated,
    })
}

fn request_dst(uri: &Uri) -> String {
    let host = uri.host().unwrap_or("unknown");
    let port = uri.port_u16().unwrap_or_else(|| default_port(uri));
    format!("{host}:{port}")
}

fn request_path(uri: &Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| "/".into(), |path| path.as_str().to_owned())
}

fn host_value(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    header_string(headers, HOST).or_else(|| uri.host().map(str::to_owned))
}

fn header_value(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn header_string(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    header_value(headers, name).map(str::to_owned)
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    header_value(headers, CONTENT_LENGTH).and_then(|value| value.parse().ok())
}

fn default_port(uri: &Uri) -> u16 {
    match uri.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => 0,
    }
}

fn version_string(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9".into(),
        Version::HTTP_10 => "HTTP/1.0".into(),
        Version::HTTP_11 => "HTTP/1.1".into(),
        Version::HTTP_2 => "HTTP/2".into(),
        Version::HTTP_3 => "HTTP/3".into(),
        _ => "HTTP/?".into(),
    }
}

fn status_line(version: Version, status: http_mitm_proxy::hyper::StatusCode) -> String {
    status.canonical_reason().map_or_else(
        || format!("{} {}", version_string(version), status.as_u16()),
        |reason| format!("{} {} {reason}", version_string(version), status.as_u16()),
    )
}

fn join_after_start_failure(thread: thread::JoinHandle<Result<()>>) -> Result<()> {
    match thread.join() {
        Ok(Ok(()) | Err(_)) => Ok(()),
        Err(_) => Err(EtwardenError::MitmProxy(
            "MITM proxy thread panicked".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_path_defaults_to_slash() {
        let uri: Uri = "https://example.com".parse().expect("uri");
        assert_eq!(request_path(&uri), "/");
    }

    #[test]
    fn request_dst_uses_default_https_port() {
        let uri: Uri = "https://example.com/path".parse().expect("uri");
        assert_eq!(request_dst(&uri), "example.com:443");
    }

    #[test]
    fn status_line_includes_reason_when_known() {
        assert_eq!(
            status_line(Version::HTTP_11, http_mitm_proxy::hyper::StatusCode::OK),
            "HTTP/1.1 200 OK"
        );
    }

    #[test]
    fn invalid_body_limits_fail() {
        let config = MitmCaptureConfig {
            listen_addr: "127.0.0.1:3003".parse().expect("addr"),
            ca: CertificateAuthorityConfig {
                cert_path: "ca.crt".into(),
                key_path: "ca.key".into(),
            },
            body_limit: 10,
            max_body_bytes: 5,
            enable_system_proxy: false,
        };
        assert!(validate_config(&config).is_err());
    }
}
