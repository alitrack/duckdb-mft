//! FILE-record decode: header + the per-record attribute walk, producing the
//! lossless [`DecodedRecord`] view used by every output function.
//!
//! All decoding goes through the `mft` crate (which applies the update-sequence
//! fixups and validates the header), wrapped so a malformed record yields a row
//! with diagnostics set rather than a panic.

use mft::attribute::header::ResidentialHeader;
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::{MftAttribute, MftEntry};
use num_traits::ToPrimitive;

use crate::data::{type_name, AttrInfo, DataStream, DataStreams, DEFAULT_RESIDENT_CAP};
use crate::file_name::{primary_index, FileName};
use crate::standard_info::StandardInfo;

/// The cheap header-only probe returned by `record_header(blob, entry)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    pub signature: String,
    pub sequence: u16,
    pub in_use: bool,
    pub is_dir: bool,
    pub base_ref: u64,
    pub lsn: u64,
    pub used_size: u32,
    pub allocated_size: u32,
}

impl RecordHeader {
    pub fn from_entry(entry: &MftEntry) -> Self {
        let h = &entry.header;
        RecordHeader {
            signature: String::from_utf8_lossy(&h.signature).into_owned(),
            sequence: h.sequence,
            in_use: entry.is_allocated(),
            is_dir: entry.is_dir(),
            base_ref: h.base_reference.entry,
            lsn: h.metadata_transaction_journal,
            used_size: h.used_entry_size,
            allocated_size: h.total_entry_size,
        }
    }
}

/// The fully-decoded per-record view (the raw, lossless representation behind
/// `mft_record`, `read_mft`, `attributes`, and `streams`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedRecord {
    pub entry: u64,
    pub sequence: u16,
    pub in_use: bool,
    pub is_dir: bool,
    pub base_ref: u64,
    pub lsn: u64,
    pub hard_link_count: u16,
    pub used_size: u32,
    pub allocated_size: u32,
    pub signature: String,
    /// Whether the update-sequence fixup validated (`Some(false)` ⇒ torn).
    pub fixup_ok: Option<bool>,
    pub standard_info: Option<StandardInfo>,
    /// Every `$FILE_NAME` (Win32 long, DOS short, one per hard link).
    pub file_names: Vec<FileName>,
    pub data: DataStreams,
    pub attributes: Vec<AttrInfo>,
    pub diagnostics: Vec<String>,
}

impl DecodedRecord {
    /// The primary `$FILE_NAME` index (prefer Win32 long name).
    pub fn primary_name_index(&self) -> Option<usize> {
        primary_index(&self.file_names)
    }

    /// The primary filename component, if any.
    pub fn primary_name(&self) -> Option<&FileName> {
        self.primary_name_index().map(|i| &self.file_names[i])
    }

    /// The single diagnostics token string for the `read_mft` column, or `None`
    /// on a clean parse.
    pub fn diagnostics_str(&self) -> Option<String> {
        if self.diagnostics.is_empty() {
            None
        } else {
            Some(self.diagnostics.join(","))
        }
    }
}

/// Decode one parsed [`MftEntry`] into a [`DecodedRecord`], capping inline
/// resident-data extraction at `resident_cap` bytes (a record claiming more is
/// reported by size but its bytes are not materialized past the cap).
pub fn decode_entry(entry: &MftEntry, resident_cap: usize) -> DecodedRecord {
    let header = RecordHeader::from_entry(entry);
    let mut diagnostics: Vec<String> = Vec::new();

    if header.signature == "BAAD" {
        diagnostics.push("baad".into());
    }
    if entry.valid_fixup == Some(false) {
        diagnostics.push("fixup-mismatch".into());
    }

    // Bounded-allocation gate: validate every attribute header against the
    // record buffer BEFORE the `mft` crate's iterator parses content. A resident
    // attribute claiming more bytes than the record holds (the 4 GB-`$DATA` bomb)
    // or a zero-length attribute (which would hang the crate's offset loop) trips
    // this gate, so the crate's allocator is never reached for a hostile record.
    if !attributes_within_bounds(entry) {
        diagnostics.push("attr-overrun".into());
        return DecodedRecord {
            entry: entry.header.record_number,
            sequence: header.sequence,
            in_use: header.in_use,
            is_dir: header.is_dir,
            base_ref: header.base_ref,
            lsn: header.lsn,
            hard_link_count: entry.header.hard_link_count,
            used_size: header.used_size,
            allocated_size: header.allocated_size,
            signature: header.signature,
            fixup_ok: entry.valid_fixup,
            standard_info: None,
            file_names: Vec::new(),
            data: DataStreams::default(),
            attributes: Vec::new(),
            diagnostics,
        };
    }

    let mut standard_info: Option<StandardInfo> = None;
    let mut file_names: Vec<FileName> = Vec::new();
    let mut attributes: Vec<AttrInfo> = Vec::new();
    let mut primary: Option<DataStream> = None;
    let mut ads: Vec<DataStream> = Vec::new();
    let mut saw_attr_list = false;

    for attr in entry.iter_attributes() {
        let attr = match attr {
            Ok(a) => a,
            Err(e) => {
                diagnostics.push(format!("decode-error:{e}"));
                break;
            }
        };

        let (resident, logical, physical) = attr_sizes(&attr);
        let type_id = attr.header.type_code.to_u32().unwrap_or(0);
        let name = if attr.header.name.is_empty() {
            None
        } else {
            Some(attr.header.name.clone())
        };

        attributes.push(AttrInfo {
            attribute_id: attr.header.instance,
            type_id,
            type_name: type_name(type_id).to_string(),
            resident,
            name: name.clone(),
            logical_size: logical,
            physical_size: physical,
            flags: attr.header.data_flags.bits(),
        });

        match attr.header.type_code {
            MftAttributeType::AttributeList => saw_attr_list = true,
            MftAttributeType::StandardInformation => {
                if let MftAttributeContent::AttrX10(si) = &attr.data {
                    standard_info = Some(StandardInfo::from_attr(si));
                }
            }
            MftAttributeType::FileName => {
                if let MftAttributeContent::AttrX30(fna) = &attr.data {
                    file_names.push(FileName::from_attr(fna));
                }
            }
            MftAttributeType::DATA => {
                let bytes = resident_bytes(&attr, resident_cap);
                let stream = DataStream {
                    name: name.clone(),
                    logical_size: logical,
                    physical_size: physical,
                    resident,
                    data: bytes,
                };
                if name.is_none() {
                    primary = Some(stream);
                } else {
                    ads.push(stream);
                }
            }
            _ => {}
        }
    }

    if saw_attr_list {
        diagnostics.push("attr-overflow".into());
    }

    DecodedRecord {
        entry: entry.header.record_number,
        sequence: header.sequence,
        in_use: header.in_use,
        is_dir: header.is_dir,
        base_ref: header.base_ref,
        lsn: header.lsn,
        hard_link_count: entry.header.hard_link_count,
        used_size: header.used_size,
        allocated_size: header.allocated_size,
        signature: header.signature,
        fixup_ok: entry.valid_fixup,
        standard_info,
        file_names,
        data: DataStreams { primary, ads },
        attributes,
        diagnostics,
    }
}

/// A minimal diagnostic-only record for a slot that could not be decoded (a
/// caught parser panic or an attribute overrun).
pub fn diagnostic_record(entry: u64, diagnostic: &str) -> DecodedRecord {
    DecodedRecord {
        entry,
        sequence: 0,
        in_use: false,
        is_dir: false,
        base_ref: 0,
        lsn: 0,
        hard_link_count: 0,
        used_size: 0,
        allocated_size: 0,
        signature: String::new(),
        fixup_ok: None,
        standard_info: None,
        file_names: Vec::new(),
        data: DataStreams::default(),
        attributes: Vec::new(),
        diagnostics: vec![diagnostic.to_string()],
    }
}

/// Maximum attributes walked in one record (loop / fan-out guard).
const MAX_ATTRS: usize = 256;

/// Cheap, allocation-free pre-scan of a record's attribute chain. Walks the
/// 16-byte common headers (plus the resident size/offset) and confirms every
/// attribute fits inside the record buffer, that resident content does not
/// exceed the buffer, and that no attribute has a zero `record_length` (which
/// would make the upstream offset loop spin forever). Returns `false` on any
/// breach so the caller can bail out before the crate allocates content.
fn attributes_within_bounds(entry: &MftEntry) -> bool {
    let data = &entry.data;
    let len = data.len();
    let mut off = entry.header.first_attribute_record_offset as usize;

    for _ in 0..MAX_ATTRS {
        // Room for the type code.
        if off + 4 > len {
            return false;
        }
        let type_code =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if type_code == 0xFFFF_FFFF {
            return true; // clean terminator
        }
        // Room for the common attribute header.
        if off + 16 > len {
            return false;
        }
        let record_length =
            u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]])
                as usize;
        // A zero / undersized / overrunning attribute is corrupt.
        if record_length < 16 || off + record_length > len {
            return false;
        }
        let resident = data[off + 8] == 0;
        if resident {
            // Resident content: data_size (u32 @ +16) bytes at data_offset
            // (u16 @ +20). Both must lie inside the record.
            let data_size = u32::from_le_bytes([
                data[off + 16],
                data[off + 17],
                data[off + 18],
                data[off + 19],
            ]) as usize;
            let data_offset = u16::from_le_bytes([data[off + 20], data[off + 21]]) as usize;
            if off + data_offset + data_size > len {
                return false;
            }
        }
        off += record_length;
    }
    // Too many attributes — treat as corrupt rather than walk further.
    false
}

/// `(resident, logical_size, physical_size)` for an attribute, from its
/// residential header.
fn attr_sizes(attr: &MftAttribute) -> (bool, u64, u64) {
    match &attr.header.residential_header {
        ResidentialHeader::Resident(r) => (true, u64::from(r.data_size), u64::from(r.data_size)),
        ResidentialHeader::NonResident(nr) => (false, nr.file_size, nr.allocated_length),
    }
}

/// The inline bytes of a resident attribute, capped at `cap`; `None` when
/// non-resident or empty.
fn resident_bytes(attr: &MftAttribute, cap: usize) -> Option<Vec<u8>> {
    if let MftAttributeContent::AttrX80(d) = &attr.data {
        let bytes = d.data();
        if bytes.is_empty() {
            return None;
        }
        let take = bytes.len().min(cap);
        return Some(bytes[..take].to_vec());
    }
    None
}

/// Default inline-resident extraction cap (re-exported for callers).
pub const RESIDENT_CAP: usize = DEFAULT_RESIDENT_CAP;
