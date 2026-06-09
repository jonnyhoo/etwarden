//! # `output::schema::line::process`
//!
//! **Purpose**: Stable process inventory, kill, and spawn-target NDJSON line types.
//! **Public API**: `ProcessLine`, `ProcessKillLine`, `SpawnTargetLine`
//! **Dependencies**: `serde`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 92 / 140

use serde::{Deserialize, Serialize};

/// One process inventory row in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessLine {
    /// Discriminator: always `"process"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    /// Executable image name.
    pub name: String,
    /// Full executable path when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Process command line when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Windows session ID when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    /// Whether this process belongs to etwarden's current session.
    pub current_session: bool,
    /// Start time in Unix seconds. `0` means unavailable.
    pub started_at_unix_secs: u64,
}

/// One exact-PID kill result line in the agent contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessKillLine {
    /// Discriminator: always `"process_kill"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Exact PID requested by caller.
    pub pid: u32,
    /// Win32 backend action.
    pub action: String,
    /// Whether termination succeeded.
    pub success: bool,
    /// Error text when termination failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Process row captured before termination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessLine>,
}

/// Spawn target discovery result emitted before capture starts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnTargetLine {
    /// Discriminator: always `"spawn_target"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Direct child PID returned by `CreateProcessW`.
    pub root_pid: u32,
    /// Primary PID used in final capture summary.
    pub primary_pid: u32,
    /// Initial process-tree PID set used by capture filters.
    pub capture_pids: Vec<u32>,
    /// Descendant PIDs that owned TCP sockets during spawn discovery.
    pub network_pids: Vec<u32>,
}

impl SpawnTargetLine {
    /// Creates a sorted spawn target line.
    #[must_use]
    pub fn new(
        root_pid: u32,
        primary_pid: u32,
        mut capture_pids: Vec<u32>,
        mut network_pids: Vec<u32>,
    ) -> Self {
        capture_pids.sort_unstable();
        network_pids.sort_unstable();
        Self {
            kind: "spawn_target".into(),
            root_pid,
            primary_pid,
            capture_pids,
            network_pids,
        }
    }
}
