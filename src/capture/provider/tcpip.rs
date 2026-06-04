//! # `capture::provider::tcpip`
//!
//! **Purpose**: Builds and parses Microsoft-Windows-Kernel-Network provider events.
//! **Public API**: `build_tcpip_provider`
//! **Dependencies**: `ferrisetw`, `parser::tcpip`, `parser::types`, `pcap::correlator`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 45 / 100

mod event;

use std::sync::Arc;

use ferrisetw::{provider::Provider, EventRecord, SchemaLocator};

use crate::{
    capture::provider::tcpip::event::parse_tcpip_event,
    parser::{tcpip::PROVIDER_TCPIP, ParserRegistry},
    pcap::correlator::Correlator,
};

/// Builds the Microsoft-Windows-Kernel-Network ETW provider.
///
/// Parses events using ferrisetw's `Parser` and dispatches `NetEvent`s to the
/// given `ParserRegistry`.
pub fn build_tcpip_provider(
    registry: Arc<ParserRegistry>,
    correlator: Option<Arc<Correlator>>,
) -> Provider {
    Provider::by_guid(PROVIDER_TCPIP)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if let Some(event) = parse_tcpip_event(record, locator) {
                if let Some(corr) = correlator.as_deref() {
                    corr.register_event(&event);
                }
                registry.push_event(event);
            }
        })
        .build()
}
