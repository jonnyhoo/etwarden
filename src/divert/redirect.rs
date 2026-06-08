//! # `divert::redirect`
//!
//! **Purpose**: Two-layer WinDivert redirect using FLOW + NETWORK handles.
//!   FLOW handle tracks which flows belong to target PIDs.
//!   NETWORK handle intercepts matching SYN packets and redirects to MITM proxy.
//! **Public API**: `DivertConfig`, `DivertHandle`, `start_divert`
//! **Dependencies**: `divert::ffi`, `divert::packet`, `divert::redirect_map`,
//!   `output::diagnostic`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 260 / 280

use std::{
    collections::HashSet,
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
        WINDIVERT_EVENT_FLOW_ESTABLISHED, WINDIVERT_FLAG_RECV_ONLY, WINDIVERT_FLAG_SNIFF,
        WINDIVERT_LAYER_FLOW, WINDIVERT_LAYER_NETWORK,
    },
    packet::{parse_ipv4_tcp, rewrite_tcp_dst, TCP_SYN},
    redirect_map::{OriginalDest, RedirectMap},
};
use crate::{
    error::{EtwardenError, Result},
    output::diagnostic,
    parser::types::{FiveTuple, Protocol},
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

/// Thread-safe set of active flows belonging to target PIDs.
type FlowTable = Arc<Mutex<HashSet<FlowKey>>>;

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
    /// Stop signal (shared with capture event loop).
    pub stop_signal: Option<Arc<AtomicBool>>,
}

/// Running WinDivert redirect threads.
pub struct DivertHandle {
    flow_handle: Arc<WinDivertHandle>,
    network_handle: Arc<WinDivertHandle>,
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
    let proxy_ip: Ipv4Addr = config
        .proxy_addr
        .ip()
        .to_string()
        .parse()
        .map_err(|_| EtwardenError::Divert("proxy addr must be IPv4 127.0.0.1".into()))?;

    // Build PID filter string for user-mode filtering in FLOW thread.
    let _pid_filter = build_pid_filter(&config.target_pids);

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
    let net_filter =
        format!("outbound and tcp and ip.DstAddr != 127.0.0.1 and tcp.DstPort != {proxy_port}");
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
                proxy_ip,
                proxy_port,
                stop2.as_deref(),
            );
        })
        .map_err(|e| EtwardenError::Divert(format!("failed to spawn redirect thread: {e}")))?;

    Ok(DivertHandle {
        flow_handle,
        network_handle,
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
        self.flow_handle.shutdown();
        self.network_handle.shutdown();
        self.join_threads()
    }

    fn join_threads(&mut self) -> Result<()> {
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
        self.flow_handle.shutdown();
        self.network_handle.shutdown();
        if let Some(t) = self.flow_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.network_thread.take() {
            let _ = t.join();
        }
    }
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
            table.insert(key);
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

fn redirect_loop(
    handle: Arc<WinDivertHandle>,
    flow_table: FlowTable,
    config: DivertConfig,
    proxy_ip: Ipv4Addr,
    proxy_port: u16,
    stop_signal: Option<&AtomicBool>,
) {
    diagnostic::info(format_args!(
        "WinDivert NETWORK redirect started (proxy={proxy_ip}:{proxy_port})"
    ));

    let mut buf = vec![0u8; PACKET_BUF_SIZE];

    loop {
        if let Some(sig) = stop_signal {
            if sig.load(Ordering::SeqCst) {
                break;
            }
        }

        let (len, addr) = match handle.recv(&mut buf) {
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

        // Only intercept new connections (SYN, no ACK).
        if parsed.tcp_flags != TCP_SYN {
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

        let matched = {
            let table = flow_table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table.contains(&lookup)
        };

        if !matched {
            // Not a target flow — reinject unchanged.
            let pkt = packet.to_vec();
            let _ = handle.send(&pkt, &addr);
            continue;
        }

        // Target flow matched — redirect to local proxy.
        diagnostic::info(format_args!(
            "REDIRECT {}:{} -> {}:{} to proxy :{proxy_port}",
            parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port
        ));

        config.redirect_map.insert(
            parsed.src_port,
            OriginalDest {
                ip: parsed.dst_ip,
                port: parsed.dst_port,
                pid: 0, // PID not needed here; MITM proxy resolves upstream from Host header
            },
        );

        // Rewrite packet in-place.
        let mut pkt = packet.to_vec();
        if !rewrite_tcp_dst(&mut pkt, proxy_ip, proxy_port, parsed.ip_header_len) {
            config.redirect_map.take(parsed.src_port);
            let _ = handle.send(&pkt, &addr);
            continue;
        }

        // Recalculate checksums.
        handle.calc_checksums(&mut pkt, &addr, 0);
        let _ = handle.send(&pkt, &addr);
    }

    diagnostic::info(format_args!("WinDivert NETWORK redirect stopped"));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a WinDivert BPF filter fragment matching any of the target PIDs.
/// Example output: `Flow.ProcessId == 1234 or Flow.ProcessId == 5678`
fn build_pid_filter(pids: &HashSet<u32>) -> String {
    let mut parts: Vec<String> = pids
        .iter()
        .map(|p| format!("Flow.ProcessId == {p}"))
        .collect();
    parts.sort(); // deterministic order
    parts.join(" or ")
}

fn flow_keys_from_tuples(tuples: &[FiveTuple]) -> HashSet<FlowKey> {
    tuples.iter().filter_map(flow_key_from_tuple).collect()
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

        assert!(keys.contains(&FlowKey {
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
}
