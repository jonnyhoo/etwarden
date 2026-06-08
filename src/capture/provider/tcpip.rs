//! # `capture::provider::tcpip`
//!
//! **Purpose**: Builds and parses Microsoft-Windows-Kernel-Network provider events.
//! **Public API**: `build_tcpip_provider`
//! **Dependencies**: `ferrisetw`, `parser::tcpip`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 49 / 100

mod connection;
mod event;

use std::sync::Arc;

use ferrisetw::{provider::Provider, EventRecord, SchemaLocator};

use crate::{
    capture::provider::tcpip::event::parse_tcpip_event, parser::ParserRegistry,
    pcap::correlator::Correlator,
};

/// Builds the TCPIP kernel provider for use with a `KernelTrace` session.
///
/// Uses the classic kernel provider GUID (`9a280ac0-c8e0-11d1-84e2-00c04fb998a2`)
/// with `EVENT_TRACE_FLAG_NETWORK_TCPIP` in `EnableFlags`. This is required
/// because `Microsoft-Windows-Kernel-Network` is a classic kernel provider
/// that does not activate via `EnableTraceEx2` alone on a `UserTrace`.
pub fn build_tcpip_provider(
    registry: Arc<ParserRegistry>,
    correlator: Option<Arc<Correlator>>,
) -> Provider {
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        if let Some(event) = parse_tcpip_event(record, locator) {
            if let Some(corr) = correlator.as_deref() {
                corr.register_event(&event);
            }
            registry.push_event(event);
        }
    };

    Provider::kernel(&ferrisetw::provider::kernel_providers::TCP_IP_PROVIDER)
        .add_callback(callback)
        .build()
}
