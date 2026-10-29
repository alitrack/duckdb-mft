//! `mft-core` — the pure NTFS `$MFT` forensic-timeline engine behind the
//! `vgi-mft` VGI worker.
//!
//! No Arrow, no VGI, no I/O policy: this crate turns a `$MFT` byte buffer into
//! decoded records, reconstructed paths, MACB timestamp quads, and a timestomp
//! score, plus the serde-serializable scan state (§C) that the worker threads
//! across DuckDB batches. All correctness lives here and is unit-tested
//! directly; the worker crate is a thin Arrow adapter over it.
//!
//! The byte-level record parse is delegated to the mature `mft` crate
//! (omerbenamram) — fixup application, header validation, attribute slicing —
//! while this crate owns the **path-reconstruction resolver, the normalized
//! timeline view, the externalized cursor, and the timestomp heuristic**.

pub mod cursor;
pub mod data;
pub mod errors;
pub mod file_name;
pub mod filetime;
pub mod parse;
pub mod record;
pub mod resolver;
pub mod standard_info;
#[cfg(any(test, feature = "synth"))]
pub mod synth;
pub mod timestomp;

use std::collections::BTreeMap;

pub use cursor::{MftCursor, MftScanState, ResolverNode, DEFAULT_MAX_DEPTH};
pub use data::{AttrInfo, DataStream, DataStreams};
pub use errors::{classify_parse_error, WellFormed, WellFormedKind};
pub use file_name::{FileName, Namespace};
pub use parse::{parse_record, quiet_parser_panics, ParseOutcome};
pub use record::{decode_entry, DecodedRecord, RecordHeader, RESIDENT_CAP};
pub use resolver::{resolve as resolve_path, ResolvedPath, ROOT_ENTRY};
pub use standard_info::{Macb, StandardInfo};
pub use timestomp::{evaluate as timestomp, Reason, Timestomp};

/// Worker/engine version (the crate version).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A decoder over one in-memory `$MFT` buffer. Owns the bytes and slices fixed
/// records itself (rather than trusting the upstream parser's stride math), so a
/// corrupt header can never overflow an index. The byte-offset cursor and
/// resolver index it produces are carried in [`MftScanState`] for cross-batch /
/// cross-process resume.
pub struct Decoder {
    bytes: Vec<u8>,
    entry_count: u64,
    record_size: u32,
    resident_cap: usize,
}

impl Decoder {
    /// Build a decoder over a `$MFT` byte buffer. Never fails: the record stride
    /// is derived from the first record's allocated-size field (with a 1024
    /// fallback), and any per-record corruption surfaces later as diagnostics.
    pub fn new(bytes: Vec<u8>) -> Result<Self, mft::err::Error> {
        Ok(Self::open(bytes, RESIDENT_CAP))
    }

    pub fn open(bytes: Vec<u8>, resident_cap: usize) -> Self {
        let record_size = record_stride(&bytes);
        let entry_count = bytes.len() as u64 / u64::from(record_size);
        Decoder {
            bytes,
            entry_count,
            record_size,
            resident_cap,
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn record_size(&self) -> u32 {
        self.record_size
    }

    /// The `record_size` bytes of entry `n`, or `None` if out of range.
    fn slice(&self, n: u64) -> Option<&[u8]> {
        let rs = self.record_size as usize;
        let start = (n as usize).checked_mul(rs)?;
        let end = start.checked_add(rs)?;
        self.bytes.get(start..end)
    }

    /// Decode entry `n`. `Ok(None)` for an empty / out-of-range slot; an
    /// `Ok(Some(record))` for a FILE / BAAD record (diagnostics carried within,
    /// including a caught parser panic).
    pub fn decode(&mut self, n: u64) -> Result<Option<DecodedRecord>, mft::err::Error> {
        let Some(slice) = self.slice(n) else {
            return Ok(None);
        };
        Ok(match parse_record(slice.to_vec(), n) {
            ParseOutcome::Empty => None,
            // decode_entry_safe wraps the crate's per-attribute content parse in a
            // catch_unwind backstop, so even a hostile record can never crash here.
            ParseOutcome::Ok(entry) => Some(parse::decode_entry_safe(&entry, n, self.resident_cap)),
            // A malformed slot still surfaces as a diagnostic-only row.
            ParseOutcome::Bad(kind, msg) => Some(record::diagnostic_record(
                n,
                &format!("{}:{}", kind.as_str(), msg),
            )),
        })
    }

    /// The raw, panic-safe `mft` entry at `n` (for header / well-formed probes).
    pub fn raw_entry(&self, n: u64) -> Option<ParseOutcome> {
        self.slice(n).map(|s| parse_record(s.to_vec(), n))
    }

    /// Build (or extend) the resolver index over every record, recording each
    /// entry's primary `$FILE_NAME` link. Carried in `state.resolver` so a child
    /// seen in a later batch still resolves against an earlier parent.
    pub fn build_resolver(&mut self, resolver: &mut BTreeMap<u64, ResolverNode>) {
        for n in 0..self.entry_count {
            let Ok(Some(rec)) = self.decode(n) else {
                continue;
            };
            if let Some(fname) = rec.primary_name() {
                resolver.insert(
                    rec.entry,
                    ResolverNode {
                        name: fname.name.clone(),
                        parent_entry: fname.parent_entry,
                        parent_seq: fname.parent_seq,
                        is_dir: rec.is_dir,
                        sequence: rec.sequence,
                    },
                );
            }
        }
        // Ensure the root (entry 5) always resolves, even if its own name record
        // was not captured.
        resolver.entry(ROOT_ENTRY).or_insert_with(|| ResolverNode {
            name: ".".into(),
            parent_entry: ROOT_ENTRY,
            parent_seq: ROOT_ENTRY as u16,
            is_dir: true,
            sequence: ROOT_ENTRY as u16,
        });
    }
}

/// The FILE-record stride in bytes, read from the first record's allocated-size
/// field (header offset `0x1C`). Returns 1024 when the buffer is too short or
/// the value is implausible (not a multiple of 512 in `[512, 65536]`).
fn record_stride(bytes: &[u8]) -> u32 {
    if bytes.len() < 0x20 || &bytes[0..4] != b"FILE" {
        return 1024;
    }
    let v = u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]]);
    if (512..=65536).contains(&v) && v.is_multiple_of(512) {
        v
    } else {
        1024
    }
}

/// Probe the header of entry `n` in `bytes` (the `record_header` scalar).
/// `Ok(None)` for an empty / out-of-range / unparseable slot.
pub fn record_header(bytes: Vec<u8>, n: u64) -> Option<RecordHeader> {
    let dec = Decoder::open(bytes, RESIDENT_CAP);
    match dec.raw_entry(n)? {
        ParseOutcome::Ok(entry) => Some(RecordHeader::from_entry(&entry)),
        _ => None,
    }
}

/// Validate entry `n` in `bytes` (the `well_formed` scalar). Never panics — a
/// corrupt / hostile record returns `ok=false` with the matching kind.
pub fn well_formed(bytes: Vec<u8>, n: u64) -> WellFormed {
    let dec = Decoder::open(bytes, RESIDENT_CAP);
    let Some(outcome) = dec.raw_entry(n) else {
        return WellFormed::bad(WellFormedKind::Truncated, "entry index out of range");
    };
    match outcome {
        ParseOutcome::Empty => WellFormed::bad(WellFormedKind::NotAnMft, "empty (zeroed) slot"),
        ParseOutcome::Bad(kind, msg) => WellFormed::bad(kind, msg),
        ParseOutcome::Ok(entry) => {
            if entry.header.signature == *b"BAAD" {
                WellFormed::bad(WellFormedKind::Baad, "record marked BAAD")
            } else if entry.valid_fixup == Some(false) {
                WellFormed::bad(
                    WellFormedKind::FixupMismatch,
                    "update-sequence fixup mismatch",
                )
            } else {
                WellFormed::ok()
            }
        }
    }
}

/// Fully decode entry `n` of `bytes` (the `mft_record` scalar). `Ok(None)` for
/// an empty slot.
pub fn decode_one(bytes: Vec<u8>, n: u64) -> Result<Option<DecodedRecord>, mft::err::Error> {
    let mut dec = Decoder::new(bytes)?;
    dec.decode(n)
}

/// Resolve entry `n`'s full path over `bytes` (the `full_path` scalar). Builds a
/// fresh resolver over the whole buffer, then walks parents.
pub fn full_path(
    bytes: Vec<u8>,
    n: u64,
    max_depth: u16,
) -> Result<Option<String>, mft::err::Error> {
    let mut dec = Decoder::new(bytes)?;
    let mut resolver = BTreeMap::new();
    dec.build_resolver(&mut resolver);
    if !resolver.contains_key(&n) {
        return Ok(None);
    }
    Ok(Some(resolve_path(&resolver, n, max_depth).path))
}
