//! # `output::schema::convert::process`
//!
//! **Purpose**: Normalizes optional process metadata for schema projection.
//! **Public API**: module-private process enrichment helper
//! **Dependencies**: `process`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 45 / 80

use crate::process::ProcessInfo;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ProcessFields {
    pub(super) name: Option<String>,
    pub(super) ppid: Option<u32>,
    pub(super) command_line: Option<String>,
    pub(super) tree_path: Option<String>,
}

impl ProcessFields {
    pub(super) fn from_name(name: Option<String>) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }

    pub(super) fn from_info(info: Option<ProcessInfo>) -> Self {
        let Some(info) = info else {
            return Self::default();
        };

        Self {
            name: Some(info.name),
            ppid: info.ppid,
            command_line: info.command_line,
            tree_path: Some(info.tree_path),
        }
    }
}
