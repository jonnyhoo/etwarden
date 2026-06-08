//! # `divert`
//!
//! **Purpose**: WinDivert-based active TCP redirect for experimental hot-attach MITM interception.
//! **Public API**: `DivertConfig`, `DivertHandle`, `start_divert`, `RedirectMap`,
//!   `OriginalDest`
//! **Dependencies**: `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 25 / 40
//!
//! ## Architecture (two-layer)
//!
//! ```text
//! FLOW handle (layer 2):
//!   Filter: outbound TCP for target PIDs (process.id == PID1 or ...)
//!   On FLOW_ESTABLISHED: record (local_port, remote_ip, remote_port) in FlowTable
//!   On FLOW_DELETED:     remove from FlowTable
//!
//! NETWORK handle (layer 0):
//!   Filter: outbound TCP, not loopback, not to proxy port
//!   On SYN: check if (src_port, dst_ip, dst_port) matches FlowTable
//!     → match: rewrite dst to 127.0.0.1:PROXY_PORT, store origin in RedirectMap
//!     → no match: reinject unchanged
//!
//! Transparent upstream resolution is not complete yet; keep `--divert` experimental.
//! ```

pub mod ffi;
pub mod packet;
pub mod redirect;
pub mod redirect_map;

pub use redirect::{start_divert, DivertConfig, DivertHandle};
pub use redirect_map::{OriginalDest, RedirectMap};
