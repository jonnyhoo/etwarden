use std::sync::Arc;

use super::*;

fn snapshot(name: &str, ppid: Option<u32>, command_line: Option<&str>) -> ProcessSnapshot {
    ProcessSnapshot {
        name: name.into(),
        ppid,
        command_line: command_line.map(str::to_owned),
    }
}

#[test]
fn cache_returns_current_process_info() {
    let cache = ProcessTreeCache::new();
    let pid = std::process::id();
    let info = cache.get_info(pid).expect("current process info");

    assert!(!info.name.is_empty(), "process name should not be empty");
    assert!(
        info.tree_path.contains(&format!("({pid})")),
        "tree path should contain current pid: {}",
        info.tree_path
    );
}

#[test]
fn cache_returns_none_for_bogus_pid() {
    let cache = ProcessTreeCache::new();
    assert!(cache.get_info(9_999_999).is_none());
}

#[test]
fn process_info_builds_parent_to_child_tree_path() {
    let entries = HashMap::from([
        (10, snapshot("explorer.exe", None, None)),
        (20, snapshot("chrome.exe", Some(10), None)),
        (
            30,
            snapshot("tab.exe", Some(20), Some("tab.exe --type=renderer")),
        ),
    ]);

    let info = process_info(30, &entries).expect("process info");
    assert_eq!(info.name, "tab.exe");
    assert_eq!(info.ppid, Some(20));
    assert_eq!(
        info.command_line.as_deref(),
        Some("tab.exe --type=renderer")
    );
    assert_eq!(
        info.tree_path,
        "explorer.exe(10) → chrome.exe(20) → tab.exe(30)"
    );
}

#[test]
fn tree_path_stops_on_parent_cycles() {
    let entries = HashMap::from([
        (10, snapshot("a.exe", Some(20), None)),
        (20, snapshot("b.exe", Some(10), None)),
    ]);

    let info = process_info(10, &entries).expect("process info");
    assert_eq!(info.tree_path, "b.exe(20) → a.exe(10)");
}

#[test]
fn descendants_or_self_returns_full_subtree() {
    let entries = HashMap::from([
        (10, snapshot("cmd.exe", None, None)),
        (20, snapshot("claude.exe", Some(10), None)),
        (30, snapshot("helper.exe", Some(20), None)),
        (40, snapshot("other.exe", None, None)),
    ]);

    let descendants = descendants_or_self(10, &entries);

    assert_eq!(descendants, HashSet::from([10, 20, 30]));
}

#[test]
fn is_descendant_or_self_handles_cycles() {
    let entries = HashMap::from([
        (10, snapshot("a.exe", Some(20), None)),
        (20, snapshot("b.exe", Some(10), None)),
    ]);

    assert!(is_descendant_or_self(10, 10, &entries));
    assert!(is_descendant_or_self(20, 10, &entries));
    assert!(!is_descendant_or_self(30, 10, &entries));
}

#[test]
fn command_line_joins_arguments() {
    let parts = [OsString::from("tool.exe"), OsString::from("--flag")];
    assert_eq!(command_line(&parts).as_deref(), Some("tool.exe --flag"));
    assert_eq!(command_line(&[]), None);
}

#[test]
fn poisoned_tree_cache_lock_returns_none_and_refresh_noops() {
    let cache = Arc::new(ProcessTreeCache::new());
    let poisoned = Arc::clone(&cache);
    let handle = std::thread::spawn(move || {
        let _guard = poisoned.inner.lock().expect("lock process tree cache");
        std::panic::resume_unwind(Box::new("poison process tree cache lock"));
    });

    assert!(handle.join().is_err());
    assert!(cache.get_info(std::process::id()).is_none());
    cache.force_refresh();
}
