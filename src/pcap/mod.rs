//! # `pcap`
//!
//! **Purpose**: Raw packet correlation and pcapng file writing.
//! **Public API**: `trait PcapSink`
//! **Dependencies**: `parser`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 22 / 60

use crate::{error::EtwardenError, parser::types::RawFrame};

/// Writes raw packet frames to a pcapng file.
pub trait PcapSink: Send {
    /// Writes a single raw frame to the pcapng output.
    ///
    /// # Arguments
    /// * `frame` — The raw Ethernet frame to write.
    /// * `pid` — The process ID attributed to this frame.
    ///
    /// # Errors
    /// Returns [`EtwardenError::PcapWrite`] if the write fails.
    fn write_frame(&mut self, frame: &RawFrame, pid: u32)
        -> std::result::Result<(), EtwardenError>;
}
