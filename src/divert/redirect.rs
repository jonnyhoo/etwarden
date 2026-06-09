//! # `divert::redirect`
//!
//! **Purpose**: Three-layer WinDivert redirect using SOCKET + FLOW + NETWORK handles.
//!   FLOW handle tracks which flows belong to target PIDs.
//!   NETWORK handle intercepts matching SYN packets and redirects to MITM proxy.
//! **Public API**: `DivertConfig`, `DivertHandle`, `start_divert`
//! **Dependencies**: `divert::ffi`, `divert::packet`, `divert::redirect_map`,
//!   `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 532 / 570

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

use super::{
    ffi::{
        WinDivertDll, WinDivertHandle, WINDIVERT_EVENT_FLOW_DELETED,
        WINDIVERT_EVENT_FLOW_ESTABLISHED, WINDIVERT_EVENT_SOCKET_CONNECT, WINDIVERT_FLAG_RECV_ONLY,
        WINDIVERT_FLAG_SNIFF, WINDIVERT_LAYER_FLOW, WINDIVERT_LAYER_NETWORK,
        WINDIVERT_LAYER_SOCKET,
    },
    packet::{parse_ipv4_tcp, rewrite_tcp_addrs, TCP_ACK, TCP_SYN},
    redirect_map::{OriginalDest, RedirectMap},
};
use crate::{
    error::{EtwardenError, Result},
    output::diagnostic,
    parser::types::{FiveTuple, Protocol},
    process::current_tcp_connections_for_pid,
};

// ---------------------------------------------------------------------------
// FlowTable — shared between FLOW and NETWORK threads
// ---------------------------------------------------------------------------

/// Key identifying a tracked flow: (local_port, remote_ip, remote_port).
/// FLOW layer gives us these in host byte order — matches packet parser output.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
}

/// Thread-safe map of active flows belonging to target PIDs: flow key → PID.
type FlowTable = Arc<Mutex<HashMap<FlowKey, u32>>>;

// ---------------------------------------------------------------------------
// Config & handle
// ---------------------------------------------------------------------------

/// Configuration for the WinDivert redirect layer.
pub struct DivertConfig {
    /// PIDs whose TCP connections should be redirected to the MITM proxy.
    pub target_pids: HashSet<u32>,
    /// Local MITM proxy listen address (must be 127.0.0.1).
    pub proxy_addr: SocketAddr,
    /// Shared redirect map — MITM proxy reads from here.
    pub redirect_map: Arc<RedirectMap>,
    /// TCP connections that existed before the FLOW handle started.
    pub existing_flows: Vec<FiveTuple>,
    /// Optional destination ports eligible for transparent redirect. Empty = all.
    pub include_ports: Vec<u16>,
    /// Destination ports excluded from transparent redirect.
    pub exclude_ports: Vec<u16>,
    /// Stop signal (shared with capture event loop).
    pub stop_signal: Option<Arc<AtomicBool>>,
}

/// Running WinDivert redirect threads.
pub struct DivertHandle {
    socket_handle: Arc<WinDivertHandle>,
    flow_handle: Arc<WinDivertHandle>,
    network_handle: Arc<WinDivertHandle>,
    socket_thread: Option<thread::JoinHandle<()>>,
    flow_thread: Option<thread::JoinHandle<()>>,
    network_thread: Option<thread::JoinHandle<()>>,
}

/// Starts the two-layer WinDivert redirect.
///
/// # Errors
/// Returns [`EtwardenError::Divert`] if WinDivert.dll cannot be loaded or
/// either handle cannot be opened.
pub fn start_divert(config: DivertConfig) -> Result<DivertHandle> {
    let dll = WinDivertDll::load()?;
    let proxy_port = config.proxy_addr.port();
    if !config.proxy_addr.is_ipv4() {
        return Err(EtwardenError::Divert("proxy addr must be IPv4".into()));
    }

    // Open SOCKET handle: sees connect() before the packet SYN reaches NETWORK.
    let socket_filter = "outbound and tcp";
    let socket_flags = WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;
    diagnostic::info(format_args!(
        "WinDivert SOCKET filter: {socket_filter}, flags=0x{socket_flags:04x}"
    ));
    let socket_handle = Arc::new(
        dll.open(socket_filter, WINDIVERT_LAYER_SOCKET, 0, socket_flags)
            .map_err(|e| EtwardenError::Divert(format!("SOCKET handle: {e}")))?,
    );

    // Open FLOW handle: tracks flows for target PIDs.
    // FLOW layer requires SNIFF | RECV_ONLY flags (cannot block/inject flows).
    let flow_filter = "true";
    let flow_flags = WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;
    diagnostic::info(format_args!(
        "WinDivert FLOW filter: {flow_filter}, flags=0x{flow_flags:04x}"
    ));
    let flow_handle = Arc::new(
        dll.open(flow_filter, WINDIVERT_LAYER_FLOW, 0, flow_flags)
            .map_err(|e| EtwardenError::Divert(format!("FLOW handle: {e}")))?,
    );

    // Open NETWORK handle: intercepts outbound SYN not to proxy/loopback.
    let net_filter = build_network_filter(proxy_port, &config.include_ports, &config.exclude_ports);
    diagnostic::info(format_args!("WinDivert NETWORK filter: {net_filter}"));
    let network_handle = Arc::new(
        dll.open(&net_filter, WINDIVERT_LAYER_NETWORK, 0, 0)
            .map_err(|e| EtwardenError::Divert(format!("NETWORK handle: {e}")))?,
    );

    let initial_flows = flow_keys_from_tuples(&config.existing_flows);
    let seeded_count = initial_flows.len();
    let flow_table: FlowTable = Arc::new(Mutex::new(initial_flows));
    if seeded_count > 0 {
        diagnostic::info(format_args!(
            "WinDivert FLOW table bootstrapped with {seeded_count} existing TCP flow(s)"
        ));
    }
    let stop = config.stop_signal.clone();
    let stop2 = stop.clone();
    let stop3 = stop.clone();

    // Spawn SOCKET monitor thread.
    let st = Arc::clone(&flow_table);
    let socket_target_pids = config.target_pids.clone();
    let socket_worker_handle = Arc::clone(&socket_handle);
    let socket_thread = thread::Builder::new()
        .name("etwarden-socket".into())
        .spawn(move || {
            socket_monitor_loop(
                socket_worker_handle,
                st,
                &socket_target_pids,
                stop3.as_deref(),
            );
        })
        .map_err(|e| EtwardenError::Divert(format!("failed to spawn socket thread: {e}")))?;

    // Spawn FLOW monitor thread.
    let ft = Arc::clone(&flow_table);
    let target_pids = config.target_pids.clone();
    let flow_worker_handle = Arc::clone(&flow_handle);
    let flow_thread = thread::Builder::new()
        .name("etwarden-flow".into())
        .spawn(move || flow_monitor_loop(flow_worker_handle, ft, &target_pids, stop.as_deref()))
        .map_err(|e| EtwardenError::Divert(format!("failed to spawn flow thread: {e}")))?;

    // Spawn NETWORK redirect thread.
    let nt = Arc::clone(&flow_table);
    let network_worker_handle = Arc::clone(&network_handle);
    let network_thread = thread::Builder::new()
        .name("etwarden-redirect".into())
        .spawn(move || {
            redirect_loop(
                network_worker_handle,
                nt,
                config,
                proxy_port,
                stop2.as_deref(),
            );
        })
        .map_err(|e| EtwardenError::Divert(format!("failed to spawn redirect thread: {e}")))?;

    Ok(DivertHandle {
        socket_handle,
        flow_handle,
        network_handle,
        socket_thread: Some(socket_thread),
        flow_thread: Some(flow_thread),
        network_thread: Some(network_thread),
    })
}

impl DivertHandle {
    /// Stops the redirect threads and waits for them to finish.
    ///
    /// # Errors
    /// Returns [`EtwardenError::Divert`] if a thread panicked.
    pub fn stop(mut self) -> Result<()> {
        self.socket_handle.shutdown();
        self.flow_handle.shutdown();
        self.network_handle.shutdown();
        self.join_threads()
    }

    fn join_threads(&mut self) -> Result<()> {
        if let Some(t) = self.socket_thread.take() {
            if t.join().is_err() {
                return Err(EtwardenError::Divert("socket thread panicked".into()));
            }
        }
        if let Some(t) = self.flow_thread.take() {
            if t.join().is_err() {
                return Err(EtwardenError::Divert("flow thread panicked".into()));
            }
        }
        if let Some(t) = self.network_thread.take() {
            if t.join().is_err() {
                return Err(EtwardenError::Divert("redirect thread panicked".into()));
            }
        }
        Ok(())
    }
}

impl Drop for DivertHandle {
    fn drop(&mut self) {
        self.socket_handle.shutdown();
        self.flow_handle.shutdown();
        self.network_handle.shutdown();
        if let Some(t) = self.socket_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.flow_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.network_thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKET monitor thread
// ---------------------------------------------------------------------------

fn socket_monitor_loop(
    handle: Arc<WinDivertHandle>,
    flow_table: FlowTable,
    target_pids: &HashSet<u32>,
    stop_signal: Option<&AtomicBool>,
) {
    diagnostic::info(format_args!("WinDivert SOCKET monitor started"));

    loop {
        if let Some(sig) = stop_signal {
            if sig.load(Ordering::SeqCst) {
                break;
            }
        }

        let mut discard = [0u8; 1];
        let Ok((_, addr)) = handle.recv(&mut discard) else {
            break;
        };
        if u32::from(addr.layer()) != WINDIVERT_LAYER_SOCKET
            || addr.event() != WINDIVERT_EVENT_SOCKET_CONNECT
        {
            continue;
        }

        let pid = addr.flow_process_id();
        if !target_pids.contains(&pid) {
            continue;
        }
        let key = FlowKey {
            local_port: addr.flow_local_port(),
            remote_ip: addr.flow_remote_addr_v4(),
            remote_port: addr.flow_remote_port(),
        };
        diagnostic::info(format_args!(
            "SOCKET connect PID={pid} local:{} -> remote:{}:{}",
            key.local_port,
            Ipv4Addr::from(key.remote_ip),
            key.remote_port,
        ));
        let mut table = flow_table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table.insert(key, pid);
    }

    diagnostic::info(format_args!("WinDivert SOCKET monitor stopped"));
}

// ---------------------------------------------------------------------------
// FLOW monitor thread
// ---------------------------------------------------------------------------

fn flow_monitor_loop(
    handle: Arc<WinDivertHandle>,
    flow_table: FlowTable,
    target_pids: &HashSet<u32>,
    stop_signal: Option<&AtomicBool>,
) {
    diagnostic::info(format_args!("WinDivert FLOW monitor started"));

    loop {
        if let Some(sig) = stop_signal {
            if sig.load(Ordering::SeqCst) {
                break;
            }
        }

        // FLOW layer doesn't use packet data, but recv still needs a buffer.
        let mut discard = [0u8; 1];
        let Ok((_, addr)) = handle.recv(&mut discard) else {
            break;
        };

        if u32::from(addr.layer()) != WINDIVERT_LAYER_FLOW {
            continue;
        }

        let event = addr.event();
        let key = FlowKey {
            local_port: addr.flow_local_port(),
            remote_ip: addr.flow_remote_addr_v4(),
            remote_port: addr.flow_remote_port(),
        };

        if event == WINDIVERT_EVENT_FLOW_ESTABLISHED {
            let pid = addr.flow_process_id();
            if !target_pids.contains(&pid) {
                continue;
            }
            let mut table = flow_table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let local_ip = Ipv4Addr::from(key.remote_ip);
            diagnostic::info(format_args!(
                "FLOW + established PID={pid} local:{} -> remote:{}:{}",
                key.local_port, local_ip, key.remote_port,
            ));
            table.insert(key, pid);
        } else if event == WINDIVERT_EVENT_FLOW_DELETED {
            let mut table = flow_table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table.remove(&key);
        }
    }

    diagnostic::info(format_args!("WinDivert FLOW monitor stopped"));
}

// ---------------------------------------------------------------------------
// NETWORK redirect thread
// ---------------------------------------------------------------------------

const PACKET_BUF_SIZE: usize = 65535;
const FLOW_MATCH_POLLS: usize = 25;
const FLOW_MATCH_SLEEP: std::time::Duration = std::time::Duration::from_millis(2);

fn redirect_loop(
    handle: Arc<WinDivertHandle>,
    flow_table: FlowTable,
    config: DivertConfig,
    proxy_port: u16,
    stop_signal: Option<&AtomicBool>,
) {
    diagnostic::info(format_args!(
        "WinDivert NETWORK redirect started (proxy=:{proxy_port})"
    ));

    let mut buf = vec![0u8; PACKET_BUF_SIZE];

    loop {
        if let Some(sig) = stop_signal {
            if sig.load(Ordering::SeqCst) {
                break;
            }
        }

        let (len, mut addr) = match handle.recv(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                diagnostic::warn(format_args!("WinDivert recv ended: {e}"));
                break;
            }
        };

        let packet = &buf[..len];
        let Some(parsed) = parse_ipv4_tcp(packet) else {
            let pkt = packet.to_vec();
            let _ = handle.send(&pkt, &addr);
            continue;
        };

        if parsed.src_port == proxy_port {
            if let Some(dest) = config.redirect_map.get(parsed.dst_port) {
                if dest.ip == parsed.dst_ip {
                    let mut pkt = packet.to_vec();
                    if rewrite_tcp_addrs(
                        &mut pkt,
                        dest.ip,
                        dest.port,
                        dest.local_ip,
                        parsed.dst_port,
                        parsed.ip_header_len,
                    ) {
                        addr.set_outbound(false);
                        handle.calc_checksums(&mut pkt, &addr, 0);
                        let _ = handle.send(&pkt, &addr);
                        continue;
                    }
                }
            }
        }

        if let Some(dest) = config.redirect_map.get(parsed.src_port) {
            if dest.ip == parsed.dst_ip && dest.port == parsed.dst_port {
                let mut pkt = packet.to_vec();
                if rewrite_tcp_addrs(
                    &mut pkt,
                    parsed.dst_ip,
                    parsed.src_port,
                    parsed.src_ip,
                    proxy_port,
                    parsed.ip_header_len,
                ) {
                    addr.set_outbound(false);
                    handle.calc_checksums(&mut pkt, &addr, 0);
                    let _ = handle.send(&pkt, &addr);
                    continue;
                }
            }
        }

        // Only intercept new outbound connections (SYN, no ACK).
        if parsed.tcp_flags & (TCP_SYN | TCP_ACK) != TCP_SYN {
            let pkt = packet.to_vec();
            let _ = handle.send(&pkt, &addr);
            continue;
        }

        // Check if this SYN matches a tracked flow.
        let lookup = FlowKey {
            local_port: parsed.src_port,
            remote_ip: parsed.dst_ip.octets(),
            remote_port: parsed.dst_port,
        };

        let mut matched_pid = {
            let table = flow_table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table.get(&lookup).copied()
        };

        if matched_pid.is_none() {
            matched_pid = pid_for_syn_from_inventory(&config.target_pids, &lookup);
            if let Some(pid) = matched_pid {
                diagnostic::info(format_args!(
                    "SYN matched PID={pid} via TCP inventory {}:{}",
                    parsed.dst_ip, parsed.dst_port
                ));
                let mut table = flow_table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                table.insert(lookup.clone(), pid);
            }
        }

        if matched_pid.is_none() {
            matched_pid = wait_for_flow_match(&flow_table, &lookup);
        }

        let Some(pid) = matched_pid else {
            // Not a target flow — reinject unchanged.
            let pkt = packet.to_vec();
            let _ = handle.send(&pkt, &addr);
            continue;
        };

        // Target flow matched — redirect to local proxy.
        diagnostic::info(format_args!(
            "REDIRECT {}:{} -> {}:{} to proxy :{proxy_port}",
            parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port
        ));

        config.redirect_map.insert(
            parsed.src_port,
            OriginalDest {
                local_ip: parsed.src_ip,
                ip: parsed.dst_ip,
                port: parsed.dst_port,
                pid,
            },
        );

        // Reflect outbound client SYN into inbound server SYN for local proxy.
        let mut pkt = packet.to_vec();
        if !rewrite_tcp_addrs(
            &mut pkt,
            parsed.dst_ip,
            parsed.src_port,
            parsed.src_ip,
            proxy_port,
            parsed.ip_header_len,
        ) {
            config.redirect_map.take(parsed.src_port);
            let _ = handle.send(&pkt, &addr);
            continue;
        }
        addr.set_outbound(false);

        // Recalculate checksums.
        handle.calc_checksums(&mut pkt, &addr, 0);
        let _ = handle.send(&pkt, &addr);
    }

    diagnostic::info(format_args!("WinDivert NETWORK redirect stopped"));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn flow_keys_from_tuples(tuples: &[FiveTuple]) -> HashMap<FlowKey, u32> {
    tuples
        .iter()
        .filter_map(flow_key_from_tuple)
        .map(|key| (key, 0))
        .collect()
}

fn wait_for_flow_match(flow_table: &FlowTable, lookup: &FlowKey) -> Option<u32> {
    for _ in 0..FLOW_MATCH_POLLS {
        std::thread::sleep(FLOW_MATCH_SLEEP);
        let matched_pid = {
            let table = flow_table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table.get(lookup).copied()
        };
        if matched_pid.is_some() {
            return matched_pid;
        }
    }
    None
}

fn pid_for_syn_from_inventory(target_pids: &HashSet<u32>, lookup: &FlowKey) -> Option<u32> {
    let mut sorted_pids: Vec<u32> = target_pids.iter().copied().collect();
    sorted_pids.sort_unstable();
    for pid in sorted_pids {
        let Ok(tuples) = current_tcp_connections_for_pid(pid) else {
            continue;
        };
        if tuples
            .iter()
            .filter_map(flow_key_from_tuple)
            .any(|key| &key == lookup)
        {
            return Some(pid);
        }
    }
    None
}

fn flow_key_from_tuple(tuple: &FiveTuple) -> Option<FlowKey> {
    if tuple.protocol != Protocol::Tcp {
        return None;
    }
    Some(FlowKey {
        local_port: tuple.src_port,
        remote_ip: tuple.dst_ip.parse::<Ipv4Addr>().ok()?.octets(),
        remote_port: tuple.dst_port,
    })
}

fn build_network_filter(proxy_port: u16, include_ports: &[u16], exclude_ports: &[u16]) -> String {
    let mut parts = vec![
        "outbound".to_string(),
        "tcp".to_string(),
        "ip.DstAddr != 127.0.0.1".to_string(),
        format!("tcp.DstPort != {proxy_port}"),
    ];
    if !include_ports.is_empty() {
        let include = include_ports
            .iter()
            .map(|port| format!("tcp.DstPort == {port}"))
            .collect::<Vec<_>>()
            .join(" or ");
        parts.push(format!("(tcp.SrcPort == {proxy_port} or {include})"));
    }
    for port in exclude_ports {
        parts.push(format!("tcp.DstPort != {port}"));
    }
    parts.join(" and ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(src_port: u16, dst_ip: &str, dst_port: u16, protocol: Protocol) -> FiveTuple {
        FiveTuple {
            src_ip: "192.168.1.100".into(),
            src_port,
            dst_ip: dst_ip.into(),
            dst_port,
            protocol,
        }
    }

    #[test]
    fn existing_ipv4_tcp_tuple_seeds_flow_key() {
        let tuple = tuple(51_000, "93.184.216.34", 443, Protocol::Tcp);

        let keys = flow_keys_from_tuples(&[tuple]);

        assert!(keys.contains_key(&FlowKey {
            local_port: 51_000,
            remote_ip: [93, 184, 216, 34],
            remote_port: 443,
        }));
    }

    #[test]
    fn non_ipv4_or_non_tcp_tuple_is_not_seeded() {
        let tuples = [
            tuple(
                51_000,
                "2606:2800:220:1:248:1893:25c8:1946",
                443,
                Protocol::Tcp,
            ),
            tuple(51_001, "93.184.216.34", 53, Protocol::Udp),
        ];

        assert!(flow_keys_from_tuples(&tuples).is_empty());
    }

    #[test]
    fn network_filter_supports_port_include_and_exclude() {
        let filter = build_network_filter(3003, &[80, 443], &[16669]);

        assert!(filter.contains("tcp.DstPort == 80"));
        assert!(filter.contains("tcp.DstPort == 443"));
        assert!(filter.contains("tcp.DstPort != 16669"));
        assert!(filter.contains("tcp.SrcPort == 3003"));
    }
}
