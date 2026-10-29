//! Externalized scan state (§C) — the serde-serializable byte-offset cursor +
//! bounded parent-resolver index that `read_mft` carries across DuckDB batches
//! and (on the HTTP transport) across worker tear-down / rehydration.
//!
//! Everything here is **plain owned data** — no handles, no file descriptors,
//! no trait objects — so a round-trip (`serialize → bytes → deserialize →
//! equal`) is lossless, which is exactly what HTTP rehydration relies on.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Default upward path-walk bound (§A.5): guards against a hostile parent loop
/// or absurd directory depth.
pub const DEFAULT_MAX_DEPTH: u16 = 256;

/// One node of the parent-resolver index: an entry's primary name + its parent
/// link, enough to reconstruct any path by walking parents to the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverNode {
    pub name: String,
    pub parent_entry: u64,
    pub parent_seq: u16,
    pub is_dir: bool,
    /// This record's own sequence number (used to detect a reused parent slot).
    pub sequence: u16,
}

/// The byte-offset cursor into the current source.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MftCursor {
    /// Which source (file path / glob match / `<blob>`) is being read.
    pub source: String,
    /// Byte offset of the next FILE record to read (record-size aligned).
    pub byte_offset: u64,
    /// Records emitted so far across the whole scan.
    pub records_emitted: u64,
}

/// The full externalized scan state threaded through `read_mft`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MftScanState {
    pub cursor: MftCursor,
    /// `entry -> (name, parent_entry, parent_seq, is_dir)` for path
    /// reconstruction (§A.5).
    pub resolver: BTreeMap<u64, ResolverNode>,
    /// Records seen before their parent (resolved on a later pass / batch).
    pub pending_paths: Vec<u64>,
    /// Record stride in bytes (usually 1024; from the boot sector / each
    /// record's own allocated size).
    pub record_size: u32,
    /// Path-walk bound (default [`DEFAULT_MAX_DEPTH`]).
    pub max_depth: u16,
    /// Whether the resolver index has been fully built for the current source.
    pub resolver_built: bool,
    /// Index of the source (glob file / blob) currently being read. Carried
    /// explicitly so a resumed scan picks up the right file — and so an
    /// end-of-scan state (index past the last source) is not mistaken for a
    /// fresh start.
    #[serde(default)]
    pub source_index: u64,
}

impl Default for MftScanState {
    fn default() -> Self {
        MftScanState {
            cursor: MftCursor::default(),
            resolver: BTreeMap::new(),
            pending_paths: Vec::new(),
            record_size: 1024,
            max_depth: DEFAULT_MAX_DEPTH,
            resolver_built: false,
            source_index: 0,
        }
    }
}

impl MftScanState {
    /// Serialize to bytes for HTTP rehydration / resume.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Restore from bytes; an empty / malformed buffer yields a fresh default.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::default();
        }
        serde_json::from_slice(bytes).unwrap_or_default()
    }

    /// The next entry index implied by the byte-offset cursor.
    pub fn next_entry(&self) -> u64 {
        if self.record_size == 0 {
            return 0;
        }
        self.cursor.byte_offset / u64::from(self.record_size)
    }

    /// Advance the cursor past `count` records of `record_size` bytes each.
    pub fn advance(&mut self, count: u64) {
        self.cursor.byte_offset += count * u64::from(self.record_size);
        self.cursor.records_emitted += count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_losslessly() {
        let mut st = MftScanState {
            record_size: 1024,
            ..Default::default()
        };
        st.resolver.insert(
            5,
            ResolverNode {
                name: ".".into(),
                parent_entry: 5,
                parent_seq: 5,
                is_dir: true,
                sequence: 5,
            },
        );
        st.cursor.source = "/cases/host01/$MFT".into();
        st.advance(42);
        st.pending_paths.push(99);

        let bytes = st.to_bytes();
        let back = MftScanState::from_bytes(&bytes);
        assert_eq!(st, back, "serialize → bytes → deserialize must be equal");
    }

    #[test]
    fn empty_bytes_is_default() {
        assert_eq!(MftScanState::from_bytes(&[]), MftScanState::default());
    }
}
