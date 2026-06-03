//! # `process::spawn`
//!
//! **Purpose**: Spawn a child process and extract its PID for capture monitoring.
//! **Public API**: `fn spawn_and_get_pid(cmd: &str) -> Result<SpawnResult>`
//! **Dependencies**: `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 165 / 180

use crate::error::EtwardenError;

/// Result of spawning a child process via `--spawn` mode.
pub struct SpawnResult {
    /// The process ID of the spawned child.
    pub pid: u32,
    /// The raw child handle — pass to `ProcessMonitor::new()`.
    pub child: std::process::Child,
}

/// Spawns a child process and returns its PID and handle without waiting.
///
/// The command string is split into program + args. Quoted paths and quoted
/// arguments are handled (e.g. `"C:\Program Files\app.exe" --name "A B"`).
///
/// # Arguments
/// * `cmd` — The command string to execute.
///
/// # Returns
/// A [`SpawnResult`] containing the child PID and process handle.
///
/// # Errors
/// Returns [`EtwardenError::ProcessSpawn`] if the spawn fails.
pub fn spawn_and_get_pid(cmd: &str) -> Result<SpawnResult, EtwardenError> {
    let (program, args) = parse_command(cmd);
    let child = std::process::Command::new(program)
        .args(&args)
        .spawn()
        .map_err(|e| EtwardenError::ProcessSpawn(format!("failed to spawn '{cmd}': {e}")))?;

    let pid = child.id();
    Ok(SpawnResult { pid, child })
}

/// Splits a command string into (program, args).
///
/// Handles quoted program paths and quoted arguments:
/// `"C:\Program Files\app.exe" --name "A B"` becomes
/// `("C:\Program Files\app.exe", ["--name", "A B"])`.
fn parse_command(cmd: &str) -> (String, Vec<String>) {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return (String::new(), Vec::new());
    }

    let (program, rest) = trimmed.strip_prefix('"').map_or_else(
        || {
            trimmed
                .find(char::is_whitespace)
                .map_or((trimmed, ""), |pos| {
                    (&trimmed[..pos], trimmed[pos..].trim())
                })
        },
        |after_quote| {
            after_quote.find('"').map_or((trimmed, ""), |end| {
                let program = &after_quote[..end];
                let rest = after_quote[end + 1..].trim();
                (program, rest)
            })
        },
    );

    let args = parse_args(rest);

    (program.to_string(), args)
}

fn parse_args(rest: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut started = false;

    for ch in rest.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }

    if started {
        args.push(current);
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let (prog, args) = parse_command("notepad.exe");
        assert_eq!(prog, "notepad.exe");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_command_with_args() {
        let (prog, args) = parse_command("ping -n 1 127.0.0.1");
        assert_eq!(prog, "ping");
        assert_eq!(args, vec!["-n", "1", "127.0.0.1"]);
    }

    #[test]
    fn parse_quoted_program() {
        let (prog, args) = parse_command(r#""C:\Program Files\app.exe" --flag value"#);
        assert_eq!(prog, r"C:\Program Files\app.exe");
        assert_eq!(args, vec!["--flag", "value"]);
    }

    #[test]
    fn parse_quoted_argument() {
        let (prog, args) = parse_command(r#"tool.exe --name "hello world" --flag"#);
        assert_eq!(prog, "tool.exe");
        assert_eq!(args, vec!["--name", "hello world", "--flag"]);
    }

    #[test]
    fn parse_empty_quoted_argument() {
        let (prog, args) = parse_command(r#"tool.exe "" tail"#);
        assert_eq!(prog, "tool.exe");
        assert_eq!(args, vec!["", "tail"]);
    }

    #[test]
    fn parse_quoted_program_no_args() {
        let (prog, args) = parse_command(r#""C:\My App\test.exe""#);
        assert_eq!(prog, r"C:\My App\test.exe");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_unclosed_quote_falls_back() {
        let (prog, args) = parse_command(r#""C:\Program Files\app.exe"#);
        assert_eq!(prog, r#""C:\Program Files\app.exe"#);
        assert!(args.is_empty());
    }

    #[test]
    fn parse_empty_string() {
        let (prog, args) = parse_command("");
        assert!(prog.is_empty());
        assert!(args.is_empty());
    }

    #[test]
    fn parse_whitespace_only() {
        let (prog, args) = parse_command("   ");
        assert!(prog.is_empty());
        assert!(args.is_empty());
    }

    #[test]
    fn spawn_cmd_exits_quickly() {
        // cmd /C exit should spawn and return a PID
        let result = spawn_and_get_pid("cmd /C exit 0");
        assert!(result.is_ok(), "spawn should succeed");
        let sr = result.expect("spawn cmd should succeed");
        assert!(sr.pid > 0, "PID should be positive");
        // child should still be accessible
        assert_eq!(sr.child.id(), sr.pid);
    }

    #[test]
    fn spawn_nonexistent_fails() {
        let result = spawn_and_get_pid("nonexistent_program_xyz_12345");
        assert!(result.is_err());
    }
}
