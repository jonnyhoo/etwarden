//! # `pcap::writer`
//!
//! **Purpose**: Writes raw packet frames to pcapng files using the `pcap-file` crate.
//! **Public API**: `struct PcapNgWriter`
//! **Dependencies**: `pcap-file`, `parser::types`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 259 / 280

use std::{borrow::Cow, fs::File, path::Path, time::Duration};

use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
        },
        PcapNgBlock, PcapNgWriter as InnerWriter,
    },
    DataLink,
};

use crate::{error::EtwardenError, parser::types::RawFrame, pcap::PcapSink};

// ---------------------------------------------------------------------------
// PcapNgWriter
// ---------------------------------------------------------------------------

/// Writes raw Ethernet frames to a pcapng file.
///
/// On creation, writes the Section Header Block (SHB) and one
/// Interface Description Block (IDB) with `DataLink::ETHERNET`.
/// Each call to `write_frame` appends an Enhanced Packet Block (EPB)
/// with the PID stored in a `Comment` option.
pub struct PcapNgWriter {
    writer: InnerWriter<File>,
}

impl PcapNgWriter {
    /// Creates a new pcapng writer that writes to the given file path.
    ///
    /// # Arguments
    /// * `path` — Output file path.
    ///
    /// # Errors
    /// Returns [`EtwardenError::PcapWrite`] if file creation or header write fails.
    pub fn create(path: &Path) -> Result<Self, EtwardenError> {
        let file = File::create(path)
            .map_err(|e| EtwardenError::PcapWrite(format!("failed to create pcapng file: {e}")))?;

        let mut writer = InnerWriter::new(file)
            .map_err(|e| EtwardenError::PcapWrite(format!("failed to write pcapng header: {e}")))?;

        // Write one IDB for Ethernet frames.
        let idb = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0xFFFF,
            options: vec![InterfaceDescriptionOption::IfTsResol(9)],
        };
        writer
            .write_block(&idb.into_block())
            .map_err(|e| EtwardenError::PcapWrite(format!("failed to write IDB: {e}")))?;

        Ok(Self { writer })
    }
}

impl PcapSink for PcapNgWriter {
    fn write_frame(&mut self, frame: &RawFrame, pid: u32) -> Result<(), EtwardenError> {
        let timestamp = pcap_timestamp(frame);

        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp,
            original_len: u32::try_from(frame.data.len()).unwrap_or(u32::MAX),
            data: Cow::Borrowed(&frame.data),
            options: vec![EnhancedPacketOption::Comment(Cow::Owned(format!(
                "pid:{pid}"
            )))],
        };

        self.writer
            .write_block(&epb.into_block())
            .map_err(|e| EtwardenError::PcapWrite(format!("failed to write EPB: {e}")))?;

        Ok(())
    }
}

fn pcap_timestamp(frame: &RawFrame) -> Duration {
    frame
        .timestamp
        .timestamp_nanos_opt()
        .and_then(|ns| u64::try_from(ns).ok())
        .map(Duration::from_nanos)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read};

    use chrono::{DateTime, Utc};
    use pcap_file::pcapng::{blocks::Block, PcapNgReader};

    use super::*;

    fn test_frame(data: &[u8]) -> RawFrame {
        test_frame_at(data, Utc::now())
    }

    fn test_frame_at(data: &[u8], timestamp: DateTime<Utc>) -> RawFrame {
        RawFrame {
            timestamp,
            data: data.to_vec(),
        }
    }

    #[test]
    fn pcap_timestamp_keeps_post_unix_nanos() {
        let timestamp = DateTime::parse_from_rfc3339("1970-01-01T00:00:01.500000100Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let frame = test_frame_at(&[], timestamp);
        assert_eq!(pcap_timestamp(&frame), Duration::new(1, 500_000_100));
    }

    #[test]
    fn pcap_timestamp_clamps_pre_unix_to_zero() {
        let timestamp = DateTime::parse_from_rfc3339("1969-12-31T23:59:59Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let frame = test_frame_at(&[], timestamp);
        assert_eq!(pcap_timestamp(&frame), Duration::ZERO);
    }

    #[test]
    fn create_writes_valid_pcapng_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pcapng");

        {
            let _writer = PcapNgWriter::create(&path).expect("create should succeed");
        }

        let mut buf = Vec::new();
        File::open(&path)
            .expect("open")
            .read_to_end(&mut buf)
            .expect("read");

        // pcapng Section Header Block starts with block type 0x0A0D0D0A
        let shb_type: [u8; 4] = 0x0A0D_0D0A_u32.to_le_bytes();
        assert!(
            buf.len() >= 12,
            "file too small for SHB: {} bytes",
            buf.len()
        );
        assert_eq!(&buf[0..4], &shb_type, "SHB block type mismatch");
    }

    #[test]
    fn create_sets_nanosecond_timestamp_resolution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pcapng");

        {
            let _writer = PcapNgWriter::create(&path).expect("create should succeed");
        }

        let file = File::open(&path).expect("open");
        let mut reader = PcapNgReader::new(BufReader::new(file)).expect("reader");
        while let Some(block) = reader.next_block() {
            if let Block::InterfaceDescription(idb) = block.expect("block") {
                assert!(idb
                    .options
                    .iter()
                    .any(|opt| matches!(opt, InterfaceDescriptionOption::IfTsResol(9))));
                return;
            }
        }

        unreachable!("expected interface description block");
    }

    #[test]
    fn write_frame_appends_epb() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pcapng");

        let frame_data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x00,
        ];

        {
            let mut writer = PcapNgWriter::create(&path).expect("create should succeed");
            writer
                .write_frame(&test_frame(&frame_data), 1234)
                .expect("write_frame should succeed");
        }

        let mut buf = Vec::new();
        File::open(&path)
            .expect("open")
            .read_to_end(&mut buf)
            .expect("read");

        // After SHB + IDB, we should have at least an EPB block.
        // EPB block type = 0x00000006
        assert!(buf.len() > 28, "expected EPB data after SHB+IDB");
    }

    #[test]
    fn create_fails_on_invalid_path() {
        let path = Path::new("/nonexistent/dir/test.pcapng");
        let result = PcapNgWriter::create(path);
        assert!(result.is_err(), "should fail on invalid path");
    }

    #[test]
    fn write_multiple_frames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pcapng");

        {
            let mut writer = PcapNgWriter::create(&path).expect("create should succeed");
            for i in 0..5u32 {
                let data = vec![u8::try_from(i % 256).expect("test"); 64];
                writer
                    .write_frame(&test_frame(&data), 100 + i)
                    .expect("write_frame should succeed");
            }
        }

        let mut buf = Vec::new();
        File::open(&path)
            .expect("open")
            .read_to_end(&mut buf)
            .expect("read");

        // Should have SHB + IDB + 5 EPBs
        assert!(buf.len() > 100, "expected multiple EPBs");
    }
}
