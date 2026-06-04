//! # `etwarden`
//!
//! **Purpose**: Process-level network capture CLI for agent runtime consumption.
//! **Public API**: `pub mod classify`, `pub mod error`, `pub mod cli`, `pub mod capture`, `pub mod parser`,
//!   `pub mod filter`, `pub mod pcap`, `pub mod process`, `pub mod output`
//! **Dependencies**: (none — crate root)
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 16 / 80

pub mod capture;
pub mod classify;
pub mod cli;
pub mod error;
pub mod filter;
pub mod mitm;
pub mod output;
pub mod parser;
pub mod pcap;
pub mod process;
pub mod tracker;
