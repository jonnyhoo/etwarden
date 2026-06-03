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

const PCAP_SNAPLEN: u32 = 0xFFFF;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

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
            snaplen: PCAP_SNAPLEN,
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
        let timestamp = pcap_timestamp(frame)?;
        let frame_len = frame_len_u32(frame.data.len())?;

        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp,
            original_len: frame_len,
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

fn frame_len_u32(len: usize) -> Result<u32, EtwardenError> {
    let len = u32::try_from(len)
        .map_err(|_| EtwardenError::PcapWrite("frame length exceeds u32".into()))?;
    if len > PCAP_SNAPLEN {
        return Err(EtwardenError::PcapWrite(format!(
            "frame length {len} exceeds pcap snaplen {PCAP_SNAPLEN}"
        )));
    }
    Ok(len)
}

fn pcap_timestamp(frame: &RawFrame) -> Result<Duration, EtwardenError> {
    let Ok(secs) = u64::try_from(frame.timestamp.timestamp()) else {
        return Ok(Duration::ZERO);
    };
    let nanos = u128::from(secs)
        .saturating_mul(NANOS_PER_SECOND)
        .saturating_add(u128::from(frame.timestamp.timestamp_subsec_nanos()));
    let nanos = u64::try_from(nanos).map_err(|_| {
        EtwardenError::PcapWrite("frame timestamp exceeds pcapng 64-bit nanosecond range".into())
    })?;
    Ok(Duration::from_nanos(nanos))
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
        assert_eq!(
            pcap_timestamp(&frame).expect("timestamp"),
            Duration::new(1, 500_000_100)
        );
    }

    #[test]
    fn pcap_timestamp_clamps_pre_unix_to_zero() {
        let timestamp = DateTime::parse_from_rfc3339("1969-12-31T23:59:59Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let frame = test_frame_at(&[], timestamp);
        assert_eq!(pcap_timestamp(&frame).expect("timestamp"), Duration::ZERO);
    }

    #[test]
    fn pcap_timestamp_keeps_future_after_i64_nanos() {
        let timestamp = DateTime::parse_from_rfc3339("2263-01-01T00:00:00.000000123Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let frame = test_frame_at(&[], timestamp);
        let secs = u64::try_from(timestamp.timestamp()).expect("post-epoch timestamp");

        assert_eq!(
            pcap_timestamp(&frame).expect("timestamp"),
            Duration::new(secs, timestamp.timestamp_subsec_nanos())
        );
    }

    #[test]
    fn pcap_timestamp_rejects_pcapng_counter_overflow() {
        let timestamp = DateTime::parse_from_rfc3339("2600-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let frame = test_frame_at(&[], timestamp);

        let err = pcap_timestamp(&frame).expect_err("timestamp should exceed pcapng range");
        assert!(err.to_string().contains("64-bit nanosecond"));
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
                assert_eq!(idb.snaplen, PCAP_SNAPLEN);
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

    #[test]
    fn write_frame_rejects_frame_larger_than_snaplen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pcapng");
        let mut writer = PcapNgWriter::create(&path).expect("create should succeed");
        let data = vec![0; PCAP_SNAPLEN as usize + 1];

        let err = writer
            .write_frame(&test_frame(&data), 1234)
            .expect_err("oversized frame should fail");

        assert!(err.to_string().contains("exceeds pcap snaplen"));
    }
}
