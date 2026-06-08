//! # `runtime::cdp`
//!
//! **Purpose**: Minimal Chrome `DevTools` Protocol client over WebSocket.
//! **Public API**: `fn discover_page_ws_url_sync`, `fn wait_for_page_load_via_ws`
//! **Dependencies**: `tokio`, `tokio-tungstenite`, `serde_json`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 160 / 200

use std::{
    io::{Read, Write},
    time::Duration,
};

use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// CDP event received from the browser.
#[derive(Debug, serde::Deserialize)]
struct CdpEvent {
    /// CDP event name (e.g. "Page.loadEventFired").
    method: Option<String>,
}

/// Performs a blocking HTTP GET to `http://127.0.0.1:{port}/json`.
///
/// Returns the response body as a String.
///
/// # Errors
/// Returns an error if the address is invalid, the connection fails,
/// or the response cannot be read.
pub fn http_get_json(port: u16) -> anyhow::Result<String> {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let host_port = format!("127.0.0.1:{port}");
    let request = format!("GET /json HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // Edge CDP server keeps connection alive despite Connection: close.
    // read_to_string would hang waiting for EOF. Use fixed-size read instead.
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        anyhow::bail!("CDP /json returned 0 bytes");
    }
    let response = String::from_utf8_lossy(&buf[..n]);
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok(body)
}

/// Discovers the page target WebSocket URL from `/json` response.
pub fn parse_page_ws_from_json(body: &str) -> Option<String> {
    let targets: Vec<serde_json::Value> = serde_json::from_str(body).ok()?;
    let page_target = targets
        .iter()
        .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("page"))
        .or_else(|| targets.first())?;
    page_target
        .get("webSocketDebuggerUrl")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Connects to CDP WebSocket, enables Page domain, waits for loadEventFired.
///
/// Creates its own single-threaded tokio runtime for the WebSocket.
/// If the page already loaded before connecting, returns success immediately.
///
/// # Errors
/// Returns an error if the runtime fails to build, the WebSocket connection
/// fails, or the page load does not occur within the timeout.
pub fn wait_for_page_load_via_ws(ws_url: &str, timeout: Duration) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async { connect_and_wait_load(ws_url, timeout).await })
}

/// Connects to CDP WebSocket, enables Page domain, waits for loadEventFired.
async fn connect_and_wait_load(ws_url: &str, timeout: Duration) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let request = ws_url.into_client_request()?;
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(request).await?;

    // Enable Page domain
    let enable_cmd = serde_json::json!({
        "id": 1,
        "method": "Page.enable"
    });
    ws_stream
        .send(Message::Text(enable_cmd.to_string().into()))
        .await?;

    // Check if page is already loaded
    let frame_cmd = serde_json::json!({
        "id": 2,
        "method": "Page.getFrameTree"
    });
    ws_stream
        .send(Message::Text(frame_cmd.to_string().into()))
        .await?;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut page_enabled = false;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            // If we got Page.enable response but no loadEventFired, the page
            // likely loaded before we connected. Return success.
            if page_enabled {
                crate::output::diagnostic::warn(format_args!(
                    "CDP: page likely loaded before WS connect, treating as success"
                ));
                return Ok(());
            }
            anyhow::bail!("CDP page load timeout");
        }

        match tokio::time::timeout(remaining, ws_stream.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(event) = serde_json::from_str::<CdpEvent>(&text) {
                    if event.method.as_deref() == Some("Page.loadEventFired") {
                        return Ok(());
                    }
                }
                // Check for command responses
                if text.contains("\"id\":1") {
                    page_enabled = true;
                }
                if text.contains("\"id\":2") && text.contains("frameTree") {
                    // Got frame tree — page exists, likely already loaded
                    crate::output::diagnostic::warn(format_args!(
                        "CDP: frame tree received, page exists"
                    ));
                    return Ok(());
                }
            }
            Ok(Some(Ok(Message::Close(_)))) => {
                anyhow::bail!("CDP WebSocket closed before page load");
            }
            Ok(Some(Err(e))) => {
                anyhow::bail!("CDP WebSocket error: {e}");
            }
            Ok(None) => {
                anyhow::bail!("CDP WebSocket stream ended before page load");
            }
            Err(_) => {
                anyhow::bail!("CDP page load timeout");
            }
            _ => {} // Ignore binary/ping/pong
        }
    }
}
