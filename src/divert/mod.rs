//! # `divert`
//!
//! **Purpose**: WinDivert TCP redirect plus TCP/UDP socket-block enforcement for process-first capture.
//! **Public API**: `DivertConfig`, `DivertHandle`, `start_divert`, `RedirectMap`,
//!   `OriginalDest`
//! **Dependencies**: `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 33 / 40
//!
//! ## Architecture (three-layer)
//!
//! ```text
//! SOCKET/FLOW handles:
//!   Observe TCP/UDP connect/flow metadata for target PIDs.
//!   Record (protocol, local_port, remote_ip, remote_port) in FlowTable.
//!
//! NETWORK handle:
//!   Filter: outbound IPv4 TCP; adds UDP only when udp_block rules exist.
//!   TCP SYN target flow: rewrite to 127.0.0.1:PROXY_PORT and store RedirectMap.
//!   TCP/UDP socket block: drop only matched target flows for enforceable rules.
//!   No match / non-target: reinject unchanged.
//!
//! Transparent proxy handles redirected TCP only; UDP is never redirected or MITM'd.
//! ```

pub mod ffi;
pub mod packet;
pub mod redirect;
pub mod redirect_map;

pub use redirect::{start_divert, DivertConfig, DivertHandle};
pub use redirect_map::{OriginalDest, RedirectMap};
