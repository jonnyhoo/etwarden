//! # `divert`
//!
//! **Purpose**: WinDivert-based active TCP redirect for process-first hot-attach HTTP capture.
//! **Public API**: `DivertConfig`, `DivertHandle`, `start_divert`, `RedirectMap`,
//!   `OriginalDest`
//! **Dependencies**: `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 25 / 40
//!
//! ## Architecture (three-layer)
//!
//! ```text
//! SOCKET/FLOW handles:
//!   Observe connect/flow metadata for target PIDs.
//!   Record (local_port, remote_ip, remote_port) in FlowTable.
//!
//! NETWORK handle:
//!   Filter: outbound IPv4 TCP, including loopback, not to proxy port
//!   On SYN: check if (src_port, dst_ip, dst_port) matches FlowTable
//!     → match: rewrite dst to 127.0.0.1:PROXY_PORT, store origin in RedirectMap
//!     → no match: reinject unchanged
//!
//! Transparent proxy then sniffs client bytes to choose HTTP, TLS MITM, or raw TCP.
//! ```

pub mod ffi;
pub mod packet;
pub mod redirect;
pub mod redirect_map;

pub use redirect::{start_divert, DivertConfig, DivertHandle};
pub use redirect_map::{OriginalDest, RedirectMap};
