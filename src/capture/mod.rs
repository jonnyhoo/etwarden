//! # `capture`
//!
//! **Purpose**: ETW session lifecycle — start, enable providers, consume events, stop.
//! **Public API**: `struct CaptureConfig`, `fn run_capture`
//! **Dependencies**: `parser`, `filter`, `output`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 5 / 60

// T08 will fill this in
