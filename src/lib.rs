//! # `etwarden`
//!
//! **Purpose**: Process-level network capture CLI for agent runtime consumption.
//! **Public API**: `pub mod capture`, `pub mod classify`, `pub mod cli`, `pub mod divert`,
//!   `pub mod error`, `pub mod filter`, `pub mod mitm`, `pub mod output`, `pub mod parser`,
//!   `pub mod pcap`, `pub mod process`, `pub mod rules`, `pub mod runtime`, `pub mod tracker`
//! **Dependencies**: (none — crate root)
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 28 / 80

pub mod capture;
pub mod classify;
pub mod cli;
pub mod divert;
pub mod error;
pub mod filter;
pub mod mitm;
pub mod output;
pub mod parser;
pub mod pcap;
pub mod process;
pub mod rules;
pub mod runtime;
pub mod tracker;
