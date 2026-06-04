//! # `capture::provider`
//!
//! **Purpose**: Builds pre-configured ferrisetw Provider instances.
//! **Public API**: `fn build_tcpip_provider()`, `fn build_ndis_provider()`
//! **Dependencies**: `ferrisetw`, `capture::timestamp`, `parser::*`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 16 / 80

mod common;
mod ndis;
mod tcpip;

pub use ndis::build_ndis_provider;
pub use tcpip::build_tcpip_provider;
