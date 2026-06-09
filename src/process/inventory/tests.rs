use std::{collections::HashSet, ffi::OsString};

use super::*;

fn entry(pid: u32, parent_pid: Option<u32>, name: &str, current_session: bool) -> ProcessEntry {
    ProcessEntry {
        pid,
        parent_pid,
        name: name.into(),
        exe: Some(format!(r"C:\Tools\{name}")),
        command_line: Some(format!("{name} --flag")),
        session_id: Some(u32::from(current_session)),
        current_session,
        started_at_unix_secs: 1000 + u64::from(pid),
    }
}

#[test]
fn filter_keeps_current_session_by_default() {
    let entries = vec![
        entry(10, None, "claude.exe", true),
        entry(20, None, "service.exe", false),
    ];

    let filtered = filter_entries(entries, &ProcessFilter::default());

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].pid, 10);
}

#[test]
fn filter_all_sessions_includes_services() {
    let entries = vec![
        entry(10, None, "claude.exe", true),
        entry(20, None, "service.exe", false),
    ];

    let filtered = filter_entries(
        entries,
        &ProcessFilter {
            all_sessions: true,
            ..ProcessFilter::default()
        },
    );

    assert_eq!(
        filtered.iter().map(|entry| entry.pid).collect::<Vec<_>>(),
        [10, 20]
    );
}

#[test]
fn filter_matches_pid_and_text() {
    let entries = vec![
        entry(10, None, "claude.exe", true),
        entry(20, None, "ccs.exe", true),
    ];

    let filtered = filter_entries(
        entries,
        &ProcessFilter {
            pid: Some(10),
            text: Some("CLAUDE".into()),
            all_sessions: false,
        },
    );

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].pid, 10);
}

#[test]
fn descendant_selection_handles_cycles() {
    let entries = vec![
        entry(10, Some(30), "root.exe", true),
        entry(20, Some(10), "child.exe", true),
        entry(30, Some(20), "cycle.exe", true),
        entry(40, None, "other.exe", true),
    ];

    let descendants = descendant_pids(10, &entries);

    assert_eq!(descendants, HashSet::from([10, 20, 30]));
}

#[test]
fn command_line_joins_os_strings() {
    let parts = [OsString::from("tool.exe"), OsString::from("--flag")];

    assert_eq!(command_line(&parts).as_deref(), Some("tool.exe --flag"));
    assert_eq!(command_line(&[]), None);
}

#[test]
fn snapshot_includes_current_process() {
    let pid = std::process::id();

    let entries = snapshot_processes();

    assert!(entries.iter().any(|entry| entry.pid == pid));
}
