//! # `capture::tests`
//!
//! **Purpose**: Unit tests for capture orchestration helpers.
//! **Public API**: test module only
//! **Dependencies**: `capture`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 23 / 80

use super::*;

#[test]
fn bootstrap_pids_falls_back_to_target_pid() {
    assert_eq!(bootstrap_pids(42, &HashSet::new()), HashSet::from([42]));
}

#[test]
fn bootstrap_pids_uses_capture_pid_set() {
    assert_eq!(
        bootstrap_pids(42, &HashSet::from([42, 99])),
        HashSet::from([42, 99])
    );
}
