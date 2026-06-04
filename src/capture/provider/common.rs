//! # `capture::provider::common`
//!
//! **Purpose**: Shared ferrisetw provider callback helpers.
//! **Public API**: module-private timestamp conversion.
//! **Dependencies**: `capture::timestamp`, `ferrisetw`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 14 / 60

use ferrisetw::EventRecord;

use crate::capture::timestamp;

pub(super) fn record_timestamp(record: &EventRecord) -> Option<chrono::DateTime<chrono::Utc>> {
    timestamp::from_filetime_100ns(record.raw_timestamp())
}
