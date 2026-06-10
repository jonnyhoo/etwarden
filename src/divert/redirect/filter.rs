//! # `divert::redirect::filter`
//!
//! **Purpose**: WinDivert NETWORK filter construction for redirect/block paths.
//! **Public API**: redirect-internal helper only
//! **Dependencies**: none
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 63 / 80

pub(super) const fn build_socket_filter(include_udp: bool) -> &'static str {
    if include_udp {
        "outbound and (tcp or udp)"
    } else {
        "outbound and tcp"
    }
}

pub(super) fn build_network_filter(
    proxy_port: u16,
    include_ports: &[u16],
    exclude_ports: &[u16],
    include_udp: bool,
) -> String {
    let tcp_filter = build_transport_filter("tcp", proxy_port, include_ports, exclude_ports, true);
    let transport_filter = if include_udp {
        let udp_filter =
            build_transport_filter("udp", proxy_port, include_ports, exclude_ports, false);
        format!("({tcp_filter} or {udp_filter})")
    } else {
        tcp_filter
    };

    ["outbound".to_string(), "ip".to_string(), transport_filter].join(" and ")
}

fn build_transport_filter(
    protocol: &str,
    proxy_port: u16,
    include_ports: &[u16],
    exclude_ports: &[u16],
    include_proxy_return: bool,
) -> String {
    let mut parts = vec![protocol.to_string()];
    if include_proxy_return {
        parts.push(format!("{protocol}.DstPort != {proxy_port}"));
    }
    if !include_ports.is_empty() {
        let include = include_ports
            .iter()
            .map(|port| format!("{protocol}.DstPort == {port}"))
            .collect::<Vec<_>>()
            .join(" or ");
        if include_proxy_return {
            parts.push(format!("({protocol}.SrcPort == {proxy_port} or {include})"));
        } else {
            parts.push(format!("({include})"));
        }
    }
    for port in exclude_ports {
        parts.push(format!("{protocol}.DstPort != {port}"));
    }
    parts.join(" and ")
}
