//! # `cli`
//!
//! **Purpose**: Command-line argument facade via clap.
//! **Public API**: `struct Cli`, `enum TargetMode`, `enum ProcessCommand`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 24 / 100

mod process;
mod root;
mod target;

pub use process::ProcessCommand;
pub use root::Cli;
pub use target::TargetMode;

#[cfg(test)]
mod tests;
