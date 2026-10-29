//! `$STANDARD_INFORMATION` (type `0x10`) — the SI MACB quad, DOS attribute
//! bitmask, and USN.

use crate::filetime::to_micros;
use mft::attribute::x10::StandardInfoAttr;

/// A **MACB** timestamp quad in `Option<i64>` microseconds since the Unix epoch
/// (`None` = unset / null `FILETIME`). Carried by both `$STANDARD_INFORMATION`
/// (SI) and each `$FILE_NAME` (FN).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Macb {
    /// **B**orn — created.
    pub created: Option<i64>,
    /// **M**odified — data last written.
    pub modified: Option<i64>,
    /// **A**ccessed — last accessed.
    pub accessed: Option<i64>,
    /// **C**hanged — MFT record last modified.
    pub mft_modified: Option<i64>,
}

/// Decoded `$STANDARD_INFORMATION`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardInfo {
    pub macb: Macb,
    /// DOS file-attribute bitmask (hidden / system / read-only / …).
    pub dos_attributes: u32,
    /// Update Sequence Number (USN) of the last change journal entry.
    pub usn: u64,
}

impl StandardInfo {
    /// Build from the `mft` crate's decoded `$STANDARD_INFORMATION`.
    pub fn from_attr(si: &StandardInfoAttr) -> Self {
        StandardInfo {
            macb: Macb {
                created: to_micros(si.created),
                modified: to_micros(si.modified),
                accessed: to_micros(si.accessed),
                mft_modified: to_micros(si.mft_modified),
            },
            dos_attributes: si.file_flags.bits(),
            usn: si.usn,
        }
    }
}
