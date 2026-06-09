//! # `process_command`
//!
//! **Purpose**: Binary-internal process subcommand routing to agent-first NDJSON lines.
//! **Public API**: binary-internal `lines`
//! **Dependencies**: `etwarden::cli`, `etwarden::output`, `etwarden::process`
//! **Platform**: `windows-only`
//! **Privilege**: `none` unless killing protected target
//! **Line budget**: 75 / 120

use etwarden::{
    cli::ProcessCommand,
    output::schema::{process_entry_to_line, process_kill_result_to_line, OutputLine},
    process::{
        inventory::{filtered_processes, process_tree, ProcessFilter},
        kill::kill_process,
    },
};

pub(super) fn lines(command: &ProcessCommand) -> anyhow::Result<Vec<OutputLine>> {
    match command {
        ProcessCommand::List { filter, pid, all } => list_lines(filter.clone(), *pid, *all),
        ProcessCommand::Tree { pid, all } => tree_lines(*pid, *all),
        ProcessCommand::Kill {
            pid,
            force,
            all,
            exit_code,
        } => kill_line(*pid, *force, *all, *exit_code),
    }
}

fn list_lines(
    filter: Option<String>,
    pid: Option<u32>,
    all_sessions: bool,
) -> anyhow::Result<Vec<OutputLine>> {
    if pid == Some(0) {
        anyhow::bail!("PID must be greater than zero");
    }
    let filter = ProcessFilter {
        pid,
        text: filter,
        all_sessions,
    };
    Ok(filtered_processes(&filter)
        .into_iter()
        .map(process_entry_to_line)
        .collect())
}

fn tree_lines(pid: u32, all_sessions: bool) -> anyhow::Result<Vec<OutputLine>> {
    if pid == 0 {
        anyhow::bail!("PID must be greater than zero");
    }
    Ok(process_tree(pid, all_sessions)
        .into_iter()
        .map(process_entry_to_line)
        .collect())
}

fn kill_line(
    pid: u32,
    force: bool,
    all_sessions: bool,
    exit_code: u32,
) -> anyhow::Result<Vec<OutputLine>> {
    if !force {
        anyhow::bail!("process kill requires --force and exact --pid");
    }
    let result = kill_process(pid, all_sessions, exit_code).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(vec![process_kill_result_to_line(result)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_requires_force() {
        let command = ProcessCommand::Kill {
            pid: 42,
            force: false,
            all: false,
            exit_code: 1,
        };

        assert!(lines(&command).is_err());
    }

    #[test]
    fn list_rejects_zero_pid() {
        let command = ProcessCommand::List {
            filter: None,
            pid: Some(0),
            all: false,
        };

        assert!(lines(&command).is_err());
    }
}
