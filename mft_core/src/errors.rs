//! `well_formed` kinds and the per-record diagnostic vocabulary.
//!
//! A `$MFT` collected from a compromised or failing host can be corrupt or
//! hostile. Every record decodes inside a per-record catch (see
//! [`crate::record`]); a malformed record yields a row (or a `well_formed`
//! struct) with a `kind` / `diagnostics` set, and the scan never aborts.

use std::fmt;

/// The classification returned by `well_formed(blob, entry)` and used as the
/// leading token of a `read_mft` `diagnostics` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WellFormedKind {
    /// A clean `FILE` record.
    Ok,
    /// Signature `BAAD` — a known-corrupt record NTFS itself flagged.
    Baad,
    /// The update-sequence-array fixup did not match (torn / corrupt record).
    FixupMismatch,
    /// Signature is neither `FILE`, `BAAD`, nor a zero (empty) slot.
    BadSignature,
    /// An attribute's declared length runs past the record buffer.
    AttrOverrun,
    /// The record buffer is shorter than a header / a declared field.
    Truncated,
    /// The bytes are not a recognizable `$MFT` FILE record at all.
    NotAnMft,
}

impl WellFormedKind {
    /// The stable lowercase token used on the wire (`well_formed.kind`, and the
    /// leading word of a `diagnostics` string).
    pub fn as_str(self) -> &'static str {
        match self {
            WellFormedKind::Ok => "ok",
            WellFormedKind::Baad => "baad",
            WellFormedKind::FixupMismatch => "fixup-mismatch",
            WellFormedKind::BadSignature => "bad-signature",
            WellFormedKind::AttrOverrun => "attr-overrun",
            WellFormedKind::Truncated => "truncated",
            WellFormedKind::NotAnMft => "not-an-mft",
        }
    }

    /// Whether this kind represents a cleanly-parsed record.
    pub fn is_ok(self) -> bool {
        matches!(self, WellFormedKind::Ok)
    }
}

impl fmt::Display for WellFormedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The structured result of `well_formed(blob, entry)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WellFormed {
    pub ok: bool,
    pub error: Option<String>,
    pub kind: WellFormedKind,
}

impl WellFormed {
    pub fn ok() -> Self {
        WellFormed {
            ok: true,
            error: None,
            kind: WellFormedKind::Ok,
        }
    }

    pub fn bad(kind: WellFormedKind, error: impl Into<String>) -> Self {
        WellFormed {
            ok: false,
            error: Some(error.into()),
            kind,
        }
    }
}

/// Classify an `mft`-crate parse error into a [`WellFormedKind`] + message. Used
/// to turn a per-record decode failure into a diagnostic rather than a panic.
pub fn classify_parse_error(err: &mft::err::Error) -> (WellFormedKind, String) {
    use mft::err::Error as E;
    let msg = err.to_string();
    let kind = match err {
        E::InvalidEntrySignature { .. } => WellFormedKind::BadSignature,
        E::IoError { .. } => WellFormedKind::Truncated,
        E::FailedToReadWindowsTime { .. } => WellFormedKind::AttrOverrun,
        _ => WellFormedKind::AttrOverrun,
    };
    (kind, msg)
}
