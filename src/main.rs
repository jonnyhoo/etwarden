//! # `etwarden` (binary entry)
//!
//! **Purpose**: Hand off to binary app runner.
//! **Public API**: (binary entry, no pub symbols)
//! **Dependencies**: `app`, `capture_command`, `process_command`, `stdout`, `target`
//! **Platform**: `windows-only`
//! **Privilege**: command-dependent
//! **Line budget**: 18 / 80

mod app;
mod capture_command;
mod process_command;
mod stdout;
mod target;

fn main() -> anyhow::Result<()> {
    app::main_entry()
}
