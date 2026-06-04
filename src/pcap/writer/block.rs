//! # `pcap::writer::block`
//!
//! **Purpose**: Builds pcapng blocks and validates packet timestamps/lengths.
//! **Public API**: module-private pcapng block builders
//! **Dependencies**: `pcap-file`, `parser::types`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 112 / 150

use std::{borrow::Cow, time::Duration};

use pcap_file::{
    pcapng::blocks::{
        enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
        interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
    },
    DataLink,
};

use crate::{error::EtwardenError, parser::types::RawFrame};

pub(super) const PCAP_SNAPLEN: u32 = 0xFFFF;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

pub(super) fn interface_block() -> InterfaceDescriptionBlock<'static> {
    InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: PCAP_SNAPLEN,
        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
    }
}

pub(super) fn enhanced_packet_block(
    frame: &RawFrame,
    pid: u32,
) -> Result<EnhancedPacketBlock<'_>, EtwardenError> {
    Ok(EnhancedPacketBlock {
        interface_id: 0,
        timestamp: pcap_timestamp(frame)?,
        original_len: frame_len_u32(frame.data.len())?,
        data: Cow::Borrowed(&frame.data),
        options: vec![EnhancedPacketOption::Comment(Cow::Owned(format!(
            "pid:{pid}"
        )))],
    })
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

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;

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
}
