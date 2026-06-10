//! # `divert::redirect::flow`
//!
//! **Purpose**: Flow-key tracking helpers for WinDivert redirect.
//! **Public API**: redirect-internal helpers only
//! **Dependencies**: `parser::types`, `process::network`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 95 / 120

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use super::{FLOW_MATCH_POLLS, FLOW_MATCH_SLEEP};
use crate::{
    parser::types::{FiveTuple, Protocol},
    process::current_tcp_connections_for_pid,
};

/// Key identifying a tracked flow: (local_port, remote_ip, remote_port).
/// FLOW layer gives us these in host byte order — matches packet parser output.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(super) struct FlowKey {
    pub(super) local_port: u16,
    pub(super) remote_ip: [u8; 4],
    pub(super) remote_port: u16,
}

/// Thread-safe map of active flows belonging to target PIDs: flow key → PID.
pub(super) type FlowTable = Arc<Mutex<HashMap<FlowKey, u32>>>;

pub(super) fn flow_table_from_tuples(tuples: &[FiveTuple]) -> (FlowTable, usize) {
    let table = flow_keys_from_tuples(tuples);
    let len = table.len();

    (Arc::new(Mutex::new(table)), len)
}

pub(super) fn flow_keys_from_tuples(tuples: &[FiveTuple]) -> HashMap<FlowKey, u32> {
    tuples
        .iter()
        .filter_map(flow_key_from_tuple)
        .map(|key| (key, 0))
        .collect()
}

pub(super) fn wait_for_flow_match(flow_table: &FlowTable, lookup: &FlowKey) -> Option<u32> {
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

pub(super) fn pid_for_syn_from_inventory(
    target_pids: &HashSet<u32>,
    lookup: &FlowKey,
) -> Option<u32> {
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
