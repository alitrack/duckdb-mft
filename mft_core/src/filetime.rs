//! Windows `FILETIME` → `TIMESTAMP` (UTC microseconds) resolution.
//!
//! The `mft` crate already decodes each on-disk `FILETIME` (a 64-bit count of
//! 100-nanosecond intervals since 1601-01-01 UTC) into a [`jiff::Timestamp`].
//! This module reduces that to the worker's wire form — `Option<i64>`
//! microseconds since the Unix epoch — applying the forensic convention that a
//! **zero / null `FILETIME`** (the 1601 sentinel many records carry for an
//! unset time) maps to `NULL`, while a real time maps to a microsecond value.
//!
//! The zero-subsecond *tell* used by the timestomp heuristic (§A.6) is
//! derivable straight from the microsecond value — a whole-second `FILETIME`
//! has `micros % 1_000_000 == 0` — so callers never need the raw 100 ns
//! fraction here.

use jiff::Timestamp;

/// Seconds from the Unix epoch back to the `FILETIME` epoch (1601-01-01 UTC).
/// A `FILETIME` of 0 decodes to exactly this instant; we treat anything at or
/// before it as an unset / null time.
pub const FILETIME_EPOCH_UNIX_SECS: i64 = -11_644_473_600;

/// Convert a decoded NTFS timestamp to `Option<i64>` microseconds since the Unix
/// epoch. A zero / 1601-sentinel `FILETIME` (an unset time) becomes `None`.
pub fn to_micros(ts: Timestamp) -> Option<i64> {
    if ts.as_second() <= FILETIME_EPOCH_UNIX_SECS {
        return None;
    }
    Some(ts.as_microsecond())
}

/// Whether a microsecond timestamp falls exactly on a whole second — the
/// "zero sub-second" anti-forensic tell (`date_part('microsecond', ts) = 0`).
/// `None` (a null time) is **not** a zero-subsecond tell.
pub fn is_zero_subsecond(micros: Option<i64>) -> bool {
    matches!(micros, Some(m) if m.rem_euclid(1_000_000) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_filetime_is_null() {
        // FILETIME 0 == 1601-01-01T00:00:00Z.
        let zero = Timestamp::from_second(FILETIME_EPOCH_UNIX_SECS).unwrap();
        assert_eq!(to_micros(zero), None);
    }

    #[test]
    fn real_time_maps_to_micros() {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        assert_eq!(to_micros(ts), Some(1_700_000_000_000_000));
    }

    #[test]
    fn zero_subsecond_detection() {
        assert!(is_zero_subsecond(Some(1_700_000_000_000_000)));
        assert!(!is_zero_subsecond(Some(1_700_000_000_000_001)));
        assert!(!is_zero_subsecond(None));
    }
}
