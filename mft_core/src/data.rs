//! `$DATA` (type `0x80`) streams + the generic attribute view.
//!
//! The unnamed `$DATA` is the file content (resident small files extracted
//! inline; non-resident → size only, runlist not followed in v1). A **named**
//! `$DATA` is an alternate data stream (ADS).

/// The default size cap (1 MiB) on inline resident-data extraction. A record
/// claiming more is reported by size but its bytes are not materialized past
/// the cap (bounded-allocation discipline).
pub const DEFAULT_RESIDENT_CAP: usize = 1024 * 1024;

/// One `$DATA` stream: the primary unnamed stream (`name == None`) or an ADS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataStream {
    /// `None` for the primary unnamed `$DATA`; `Some(name)` for an ADS.
    pub name: Option<String>,
    pub logical_size: u64,
    pub physical_size: u64,
    pub resident: bool,
    /// Inline bytes when resident (size-capped); `None` when non-resident.
    pub data: Option<Vec<u8>>,
}

/// All `$DATA` streams of a record: the primary (if present) + every ADS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataStreams {
    pub primary: Option<DataStream>,
    pub ads: Vec<DataStream>,
}

impl DataStreams {
    /// The primary stream's logical size, or 0 when absent.
    pub fn logical_size(&self) -> u64 {
        self.primary.as_ref().map(|d| d.logical_size).unwrap_or(0)
    }

    /// The primary stream's physical (allocated) size, or 0 when absent.
    pub fn physical_size(&self) -> u64 {
        self.primary.as_ref().map(|d| d.physical_size).unwrap_or(0)
    }

    /// The primary resident bytes, if resident.
    pub fn resident_bytes(&self) -> Option<&[u8]> {
        self.primary.as_ref().and_then(|d| d.data.as_deref())
    }

    /// Every stream in emission order: primary first, then each ADS.
    pub fn iter(&self) -> impl Iterator<Item = &DataStream> {
        self.primary.iter().chain(self.ads.iter())
    }
}

/// A generic per-attribute view (the `mft_dump`-style deep view), one per
/// attribute in a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttrInfo {
    pub attribute_id: u16,
    pub type_id: u32,
    pub type_name: String,
    pub resident: bool,
    /// The attribute name (e.g. an ADS name); `None` when unnamed.
    pub name: Option<String>,
    pub logical_size: u64,
    pub physical_size: u64,
    pub flags: u16,
}

/// The canonical `$NAME` of an NTFS attribute type code.
pub fn type_name(type_id: u32) -> &'static str {
    match type_id {
        0x10 => "$STANDARD_INFORMATION",
        0x20 => "$ATTRIBUTE_LIST",
        0x30 => "$FILE_NAME",
        0x40 => "$OBJECT_ID",
        0x50 => "$SECURITY_DESCRIPTOR",
        0x60 => "$VOLUME_NAME",
        0x70 => "$VOLUME_INFORMATION",
        0x80 => "$DATA",
        0x90 => "$INDEX_ROOT",
        0xA0 => "$INDEX_ALLOCATION",
        0xB0 => "$BITMAP",
        0xC0 => "$REPARSE_POINT",
        0xD0 => "$EA_INFORMATION",
        0xE0 => "$EA",
        0x100 => "$LOGGED_UTILITY_STREAM",
        _ => "$UNKNOWN",
    }
}
