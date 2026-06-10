//! # `divert::redirect::filter`
//!
//! **Purpose**: WinDivert NETWORK filter construction for redirect/block paths.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: none
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 34 / 80

pub(super) fn build_network_filter(
    proxy_port: u16,
    include_ports: &[u16],
    exclude_ports: &[u16],
    include_udp: bool,
) -> String {
    let mut tcp_parts = vec!["tcp".to_string(), format!("tcp.DstPort != {proxy_port}")];
    if !include_ports.is_empty() {
        let include = include_ports
            .iter()
            .map(|port| format!("tcp.DstPort == {port}"))
            .collect::<Vec<_>>()
            .join(" or ");
        tcp_parts.push(format!("(tcp.SrcPort == {proxy_port} or {include})"));
    }
    for port in exclude_ports {
        tcp_parts.push(format!("tcp.DstPort != {port}"));
    }

    let tcp_filter = tcp_parts.join(" and ");
    let transport_filter = if include_udp {
        format!("({tcp_filter} or udp)")
    } else {
        tcp_filter
    };

    ["outbound".to_string(), "ip".to_string(), transport_filter].join(" and ")
}
