//! Synthetic `$MFT` builder — byte-accurate FILE-record construction for
//! deterministic golden fixtures (resident + non-resident `$DATA`, multiple
//! `$FILE_NAME`s, timestomp cases, orphans). Test-support only (gated behind
//! `cfg(any(test, feature = "synth"))`).
//!
//! Records are 1024 bytes, with a valid update-sequence-array (fixup) so the
//! `mft` crate parses them exactly as it would a real on-disk record. The
//! builder lays out attributes, writes the `0xFFFFFFFF` terminator, then applies
//! the fixup (saving the real sector-tail bytes into the USA and writing the
//! update-sequence value into the tails) so the round-trip validates.

#![cfg(any(test, feature = "synth"))]

const RECORD_SIZE: usize = 1024;
const SECTOR: usize = 512;
const USA_OFFSET: usize = 0x30;
const USA_SIZE: u16 = 3; // 1 update-seq + 2 fixups (1024 / 512 = 2 sectors)
const FIRST_ATTR_OFFSET: usize = 0x38;
const UPDATE_SEQ: [u8; 2] = [0x01, 0x00];

/// 100 ns intervals between the FILETIME epoch (1601) and the Unix epoch (1970).
const FILETIME_UNIX_DELTA: i64 = 11_644_473_600;

/// Build a Windows `FILETIME` (100 ns since 1601) from whole Unix seconds — a
/// **zero sub-second** value (the timestomp tell).
pub fn filetime_secs(unix_secs: i64) -> u64 {
    ((unix_secs + FILETIME_UNIX_DELTA) * 10_000_000) as u64
}

/// Build a `FILETIME` from Unix microseconds (carries a sub-second fraction).
pub fn filetime_micros(unix_micros: i64) -> u64 {
    let base = (unix_micros / 1_000_000 + FILETIME_UNIX_DELTA) * 10_000_000;
    let frac = (unix_micros % 1_000_000) * 10; // µs → 100 ns units
    (base + frac) as u64
}

/// A MACB quad in raw `FILETIME` units.
#[derive(Clone, Copy)]
pub struct Times {
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
}

impl Times {
    /// All four equal, from whole Unix seconds.
    pub fn uniform_secs(unix_secs: i64) -> Self {
        let f = filetime_secs(unix_secs);
        Times {
            created: f,
            modified: f,
            mft_modified: f,
            accessed: f,
        }
    }

    /// All four equal, from Unix microseconds (sub-second fraction preserved).
    pub fn uniform_micros(unix_micros: i64) -> Self {
        let f = filetime_micros(unix_micros);
        Times {
            created: f,
            modified: f,
            mft_modified: f,
            accessed: f,
        }
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.created.to_le_bytes());
        out.extend_from_slice(&self.modified.to_le_bytes());
        out.extend_from_slice(&self.mft_modified.to_le_bytes());
        out.extend_from_slice(&self.accessed.to_le_bytes());
    }
}

fn utf16le(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn round8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// Encode a resident attribute (header + resident header + optional name +
/// content), padded to an 8-byte multiple.
fn resident_attr(type_id: u32, instance: u16, name: Option<&str>, content: &[u8]) -> Vec<u8> {
    let name_bytes = name.map(utf16le).unwrap_or_default();
    let name_units = name.map(|n| n.encode_utf16().count()).unwrap_or(0) as u8;
    let name_offset = if name_units > 0 { 24u16 } else { 0 };
    let data_offset = 24 + name_bytes.len();
    let body_len = data_offset + content.len();
    let record_length = round8(body_len);

    let mut a = Vec::with_capacity(record_length);
    a.extend_from_slice(&type_id.to_le_bytes()); // 0x00 type_code
    a.extend_from_slice(&(record_length as u32).to_le_bytes()); // 0x04 length
    a.push(0); // 0x08 resident
    a.push(name_units); // 0x09 name_size
    a.extend_from_slice(&name_offset.to_le_bytes()); // 0x0A name_offset
    a.extend_from_slice(&0u16.to_le_bytes()); // 0x0C data_flags
    a.extend_from_slice(&instance.to_le_bytes()); // 0x0E instance
    a.extend_from_slice(&(content.len() as u32).to_le_bytes()); // 0x10 data_size
    a.extend_from_slice(&(data_offset as u16).to_le_bytes()); // 0x14 data_offset
    a.push(0); // 0x16 index_flag
    a.push(0); // 0x17 padding
    a.extend_from_slice(&name_bytes); // name at 0x18
    a.extend_from_slice(content); // content at data_offset
    a.resize(record_length, 0);
    a
}

/// Encode a non-resident attribute (size-only; an empty data-run list).
fn non_resident_attr(
    type_id: u32,
    instance: u16,
    name: Option<&str>,
    logical_size: u64,
    physical_size: u64,
) -> Vec<u8> {
    let name_bytes = name.map(utf16le).unwrap_or_default();
    let name_units = name.map(|n| n.encode_utf16().count()).unwrap_or(0) as u8;
    // Layout: 16-byte common header, 48-byte non-resident header, optional name,
    // then the data runs (a single 0x00 end marker → empty run list).
    let nr_header_end = 16 + 48;
    let name_offset = if name_units > 0 {
        nr_header_end as u16
    } else {
        0
    };
    let datarun_offset = nr_header_end + name_bytes.len();
    let record_length = round8(datarun_offset + 1);

    let mut a = Vec::with_capacity(record_length);
    a.extend_from_slice(&type_id.to_le_bytes()); // type_code
    a.extend_from_slice(&(record_length as u32).to_le_bytes()); // length
    a.push(1); // non-resident
    a.push(name_units);
    a.extend_from_slice(&name_offset.to_le_bytes());
    a.extend_from_slice(&0u16.to_le_bytes()); // data_flags
    a.extend_from_slice(&instance.to_le_bytes());
    // non-resident header (48 bytes; unit_compression_size = 0 → no total_allocated)
    a.extend_from_slice(&0u64.to_le_bytes()); // vnc_first
    a.extend_from_slice(&0u64.to_le_bytes()); // vnc_last
    a.extend_from_slice(&(datarun_offset as u16).to_le_bytes()); // datarun_offset
    a.extend_from_slice(&0u16.to_le_bytes()); // unit_compression_size
    a.extend_from_slice(&0u32.to_le_bytes()); // padding
    a.extend_from_slice(&physical_size.to_le_bytes()); // allocated_length
    a.extend_from_slice(&logical_size.to_le_bytes()); // file_size
    a.extend_from_slice(&logical_size.to_le_bytes()); // valid_data_length
    a.extend_from_slice(&name_bytes);
    a.resize(record_length, 0); // datarun area is zeros → empty run list
    a
}

/// `$STANDARD_INFORMATION` (0x10) content.
fn standard_info_content(t: &Times, dos_flags: u32, usn: u64) -> Vec<u8> {
    let mut c = Vec::with_capacity(72);
    t.write_into(&mut c);
    c.extend_from_slice(&dos_flags.to_le_bytes()); // file_flags
    c.extend_from_slice(&0u32.to_le_bytes()); // max_version
    c.extend_from_slice(&0u32.to_le_bytes()); // version
    c.extend_from_slice(&0u32.to_le_bytes()); // class_id
    c.extend_from_slice(&0u32.to_le_bytes()); // owner_id
    c.extend_from_slice(&0u32.to_le_bytes()); // security_id
    c.extend_from_slice(&0u64.to_le_bytes()); // quota
    c.extend_from_slice(&usn.to_le_bytes()); // usn
    c
}

/// `$FILE_NAME` (0x30) content.
#[allow(clippy::too_many_arguments)]
fn file_name_content(
    parent_entry: u64,
    parent_seq: u16,
    t: &Times,
    logical: u64,
    physical: u64,
    flags: u32,
    namespace: u8,
    name: &str,
) -> Vec<u8> {
    let mut c = Vec::new();
    let parent_ref = (parent_entry & 0x0000_FFFF_FFFF_FFFF) | ((parent_seq as u64) << 48);
    c.extend_from_slice(&parent_ref.to_le_bytes());
    t.write_into(&mut c);
    c.extend_from_slice(&logical.to_le_bytes());
    c.extend_from_slice(&physical.to_le_bytes());
    c.extend_from_slice(&flags.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes()); // reparse_value
    c.push(name.encode_utf16().count() as u8); // name_length
    c.push(namespace);
    c.extend_from_slice(&utf16le(name));
    c
}

/// NTFS filename namespaces.
pub mod ns {
    pub const POSIX: u8 = 0;
    pub const WIN32: u8 = 1;
    pub const DOS: u8 = 2;
    pub const WIN32_AND_DOS: u8 = 3;
}

/// A FILE record under construction.
pub struct RecordBuilder {
    entry: u64,
    sequence: u16,
    hard_link_count: u16,
    flags: u16,
    base_ref: u64,
    lsn: u64,
    next_instance: u16,
    attrs: Vec<u8>,
    /// Force a bad signature / BAAD for malformed fixtures.
    override_signature: Option<[u8; 4]>,
    break_fixup: bool,
}

impl RecordBuilder {
    pub fn new(entry: u64, sequence: u16) -> Self {
        RecordBuilder {
            entry,
            sequence,
            hard_link_count: 1,
            flags: 0x01, // allocated
            base_ref: 0,
            lsn: 0,
            next_instance: 0,
            attrs: Vec::new(),
            override_signature: None,
            break_fixup: false,
        }
    }

    pub fn allocated(mut self, yes: bool) -> Self {
        if yes {
            self.flags |= 0x01;
        } else {
            self.flags &= !0x01;
        }
        self
    }

    pub fn directory(mut self, yes: bool) -> Self {
        if yes {
            self.flags |= 0x02;
        } else {
            self.flags &= !0x02;
        }
        self
    }

    pub fn hard_links(mut self, n: u16) -> Self {
        self.hard_link_count = n;
        self
    }

    pub fn lsn(mut self, lsn: u64) -> Self {
        self.lsn = lsn;
        self
    }

    pub fn baad(mut self) -> Self {
        self.override_signature = Some(*b"BAAD");
        self
    }

    pub fn bad_signature(mut self) -> Self {
        self.override_signature = Some(*b"JUNK");
        self
    }

    pub fn break_fixup(mut self) -> Self {
        self.break_fixup = true;
        self
    }

    fn instance(&mut self) -> u16 {
        let i = self.next_instance;
        self.next_instance += 1;
        i
    }

    pub fn standard_info(mut self, t: Times, dos_flags: u32, usn: u64) -> Self {
        let inst = self.instance();
        let content = standard_info_content(&t, dos_flags, usn);
        self.attrs.extend(resident_attr(0x10, inst, None, &content));
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn file_name(
        mut self,
        parent_entry: u64,
        parent_seq: u16,
        t: Times,
        logical: u64,
        physical: u64,
        flags: u32,
        namespace: u8,
        name: &str,
    ) -> Self {
        let inst = self.instance();
        let content = file_name_content(
            parent_entry,
            parent_seq,
            &t,
            logical,
            physical,
            flags,
            namespace,
            name,
        );
        self.attrs.extend(resident_attr(0x30, inst, None, &content));
        self
    }

    /// A resident unnamed `$DATA` (inline file content).
    pub fn data_resident(mut self, content: &[u8]) -> Self {
        let inst = self.instance();
        self.attrs.extend(resident_attr(0x80, inst, None, content));
        self
    }

    /// A non-resident unnamed `$DATA` (size only).
    pub fn data_non_resident(mut self, logical: u64, physical: u64) -> Self {
        let inst = self.instance();
        self.attrs
            .extend(non_resident_attr(0x80, inst, None, logical, physical));
        self
    }

    /// A named `$DATA` (an alternate data stream) carrying resident bytes.
    pub fn ads_resident(mut self, name: &str, content: &[u8]) -> Self {
        let inst = self.instance();
        self.attrs
            .extend(resident_attr(0x80, inst, Some(name), content));
        self
    }

    /// Serialize this record to its 1024 fixed bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![0u8; RECORD_SIZE];
        let sig = self.override_signature.unwrap_or(*b"FILE");
        buf[0..4].copy_from_slice(&sig);
        buf[0x04..0x06].copy_from_slice(&(USA_OFFSET as u16).to_le_bytes());
        buf[0x06..0x08].copy_from_slice(&USA_SIZE.to_le_bytes());
        buf[0x08..0x10].copy_from_slice(&self.lsn.to_le_bytes());
        buf[0x10..0x12].copy_from_slice(&self.sequence.to_le_bytes());
        buf[0x12..0x14].copy_from_slice(&self.hard_link_count.to_le_bytes());
        buf[0x14..0x16].copy_from_slice(&(FIRST_ATTR_OFFSET as u16).to_le_bytes());
        buf[0x16..0x18].copy_from_slice(&self.flags.to_le_bytes());
        buf[0x20..0x28].copy_from_slice(&self.base_ref.to_le_bytes());
        buf[0x28..0x2A].copy_from_slice(&self.next_instance.to_le_bytes());

        // Attributes + terminator.
        let mut off = FIRST_ATTR_OFFSET;
        let end = off + self.attrs.len();
        assert!(end + 4 <= RECORD_SIZE, "synthetic record overflows 1024 B");
        buf[off..end].copy_from_slice(&self.attrs);
        off = end;
        buf[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        off += 4;
        buf[0x18..0x1C].copy_from_slice(&(off as u32).to_le_bytes()); // used size
        buf[0x1C..0x20].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes()); // alloc size

        // Apply the update-sequence-array fixup so the record validates.
        // Save the real sector-tail bytes into the USA fixup slots, then write
        // the update-sequence value into both the USA[0] and the sector tails.
        if sig == *b"FILE" {
            let tail1 = [buf[SECTOR - 2], buf[SECTOR - 1]];
            let tail2 = [buf[2 * SECTOR - 2], buf[2 * SECTOR - 1]];
            buf[USA_OFFSET..USA_OFFSET + 2].copy_from_slice(&UPDATE_SEQ);
            buf[USA_OFFSET + 2..USA_OFFSET + 4].copy_from_slice(&tail1);
            buf[USA_OFFSET + 4..USA_OFFSET + 6].copy_from_slice(&tail2);
            // Write the sentinel into the sector tails (the on-disk form).
            buf[SECTOR - 2..SECTOR].copy_from_slice(&UPDATE_SEQ);
            buf[2 * SECTOR - 2..2 * SECTOR].copy_from_slice(&UPDATE_SEQ);
            if self.break_fixup {
                // Corrupt the second sector tail so the fixup check fails.
                buf[2 * SECTOR - 1] = 0xEE;
            }
        }
        buf
    }
}

/// Concatenate records (ordered by entry number, gaps zero-filled) into a
/// single `$MFT` byte image.
pub struct MftBuilder {
    records: Vec<(u64, Vec<u8>)>,
}

impl Default for MftBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MftBuilder {
    pub fn new() -> Self {
        MftBuilder {
            records: Vec::new(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, rec: &RecordBuilder) -> Self {
        self.records.push((rec.entry, rec.build()));
        self
    }

    /// Build the contiguous `$MFT` image. Entry 0 must be present (the parser
    /// reads it to derive the record stride); missing entries below the max are
    /// zero-filled empty slots.
    pub fn finish(mut self) -> Vec<u8> {
        self.records.sort_by_key(|(e, _)| *e);
        let max_entry = self.records.last().map(|(e, _)| *e).unwrap_or(0);
        let mut out = vec![0u8; ((max_entry + 1) as usize) * RECORD_SIZE];
        for (entry, bytes) in &self.records {
            let start = (*entry as usize) * RECORD_SIZE;
            out[start..start + RECORD_SIZE].copy_from_slice(bytes);
        }
        out
    }
}
