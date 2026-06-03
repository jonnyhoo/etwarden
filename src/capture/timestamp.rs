//! # `capture::timestamp`
//!
//! **Purpose**: Converts ETW raw FILETIME timestamps into UTC datetimes.
//! **Public API**: `fn from_filetime_100ns`
//! **Dependencies**: `chrono`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 57 / 100

use chrono::{DateTime, TimeZone, Utc};

/// Number of 100ns intervals between Windows FILETIME epoch and Unix epoch.
const FILETIME_UNIX_EPOCH_100NS: i64 = 116_444_736_000_000_000;
/// Number of 100ns intervals per second.
const FILETIME_TICKS_PER_SECOND: i64 = 10_000_000;
/// Nanoseconds represented by one FILETIME tick.
const NANOS_PER_FILETIME_TICK: i64 = 100;

/// Converts an ETW `EVENT_HEADER.TimeStamp` FILETIME value into UTC.
#[must_use]
pub(super) fn from_filetime_100ns(raw: i64) -> Option<DateTime<Utc>> {
    let unix_100ns = raw.checked_sub(FILETIME_UNIX_EPOCH_100NS)?;
    let seconds = unix_100ns.div_euclid(FILETIME_TICKS_PER_SECOND);
    let subsecond_100ns = unix_100ns.rem_euclid(FILETIME_TICKS_PER_SECOND);
    let nanos = u32::try_from(subsecond_100ns * NANOS_PER_FILETIME_TICK).ok()?;
    Utc.timestamp_opt(seconds, nanos).single()
}

#[cfg(test)]
mod tests {
    use chrono::{Datelike, Timelike};

    use super::*;

    #[test]
    fn unix_epoch_converts() {
        let ts = from_filetime_100ns(FILETIME_UNIX_EPOCH_100NS).expect("valid timestamp");
        assert_eq!(ts.to_rfc3339(), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn subsecond_precision_converts() {
        let raw = FILETIME_UNIX_EPOCH_100NS + 15_000_001;
        let ts = from_filetime_100ns(raw).expect("valid timestamp");
        assert_eq!(ts.second(), 1);
        assert_eq!(ts.nanosecond(), 500_000_100);
    }

    #[test]
    fn pre_unix_timestamp_converts() {
        let raw = FILETIME_UNIX_EPOCH_100NS - FILETIME_TICKS_PER_SECOND;
        let ts = from_filetime_100ns(raw).expect("valid timestamp");
        assert_eq!(ts.year(), 1969);
        assert_eq!(ts.second(), 59);
    }
}
