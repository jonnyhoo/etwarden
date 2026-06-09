//! # `process::spawn_capture`
//!
//! **Purpose**: Resolve capture PID sets for spawned process trees.
//! **Public API**: `struct SpawnCaptureTarget`, `fn resolve_spawn_capture_target`
//! **Dependencies**: `process::network`, `process::tree`, `output::diagnostic`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 138 / 180

use std::{collections::HashSet, thread, time::Duration};

use super::{
    network::{current_tcp_owners_with_connections, TcpOwnerConnections},
    tree::ProcessTreeCache,
};
use crate::{error::EtwardenError, output::diagnostic};

const DISCOVERY_POLLS: usize = 20;
const DISCOVERY_INTERVAL: Duration = Duration::from_millis(50);

/// Capture target resolved from a spawned root process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnCaptureTarget {
    pub root_pid: u32,
    pub pids: HashSet<u32>,
    pub network_pids: HashSet<u32>,
}

/// Resolves a spawned root PID to root + current descendant network owners.
///
/// # Arguments
/// * `root_pid` — Direct child PID returned by process spawn.
/// * `process_cache` — Process snapshot cache used to discover descendants.
/// * `wait_for_descendant` — Whether to briefly wait for wrapper commands to spawn a child.
///
/// # Returns
/// A capture target with the spawned root, descendants, and network-owning PIDs.
///
/// # Errors
/// Returns [`EtwardenError::NetworkInventory`] if socket inventory fails.
pub fn resolve_spawn_capture_target(
    root_pid: u32,
    process_cache: &ProcessTreeCache,
    wait_for_descendant: bool,
) -> Result<SpawnCaptureTarget, EtwardenError> {
    let target = snapshot_spawn_capture_target(root_pid, process_cache, wait_for_descendant)?;
    if target.network_pids.is_empty() {
        diagnostic::warn(format_args!(
            "spawned PID {root_pid} has no descendant TCP owner yet; capturing process tree"
        ));
    } else {
        diagnostic::warn(format_args!(
            "spawned PID {root_pid} network PIDs: {}",
            sorted_pid_list(&target.network_pids)
        ));
    }
    Ok(target)
}

fn snapshot_spawn_capture_target(
    root_pid: u32,
    process_cache: &ProcessTreeCache,
    wait_for_descendant: bool,
) -> Result<SpawnCaptureTarget, EtwardenError> {
    let mut latest_pids;
    let mut latest_network_pids;
    for attempt in 0..DISCOVERY_POLLS {
        process_cache.force_refresh();
        latest_pids = process_cache.descendants_or_self(root_pid);
        let owners = current_tcp_owners_with_connections(&latest_pids)?;
        latest_network_pids = network_pids(&owners);
        if latest_pids.len() > 1 || !latest_network_pids.is_empty() {
            return Ok(SpawnCaptureTarget {
                root_pid,
                pids: latest_pids,
                network_pids: latest_network_pids,
            });
        }
        if !wait_for_descendant {
            return Ok(SpawnCaptureTarget {
                root_pid,
                pids: latest_pids,
                network_pids: latest_network_pids,
            });
        }
        if attempt + 1 < DISCOVERY_POLLS {
            thread::sleep(DISCOVERY_INTERVAL);
        }
    }

    Ok(SpawnCaptureTarget {
        root_pid,
        pids: process_cache.descendants_or_self(root_pid),
        network_pids: HashSet::new(),
    })
}

fn network_pids(owners: &[TcpOwnerConnections]) -> HashSet<u32> {
    owners
        .iter()
        .filter(|owner| !owner.connections.is_empty())
        .map(|owner| owner.pid)
        .collect()
}

fn sorted_pid_list(pids: &HashSet<u32>) -> String {
    let mut sorted: Vec<u32> = pids.iter().copied().collect();
    sorted.sort_unstable();
    sorted
        .into_iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::{FiveTuple, Protocol};

    fn owner(pid: u32, connections: Vec<FiveTuple>) -> TcpOwnerConnections {
        TcpOwnerConnections { pid, connections }
    }

    fn tuple() -> FiveTuple {
        FiveTuple {
            src_ip: "127.0.0.1".into(),
            src_port: 50_000,
            dst_ip: "127.0.0.1".into(),
            dst_port: 443,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn network_pids_keep_only_owners_with_connections() {
        let owners = [owner(10, Vec::new()), owner(20, vec![tuple()])];

        assert_eq!(network_pids(&owners), HashSet::from([20]));
    }

    #[test]
    fn pid_list_is_stable() {
        assert_eq!(sorted_pid_list(&HashSet::from([30, 10, 20])), "10,20,30");
    }
}
