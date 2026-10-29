//! `$FILE_NAME` (type `0x30`) — parent reference, the FN MACB quad, logical /
//! physical size, the name and its namespace.

use crate::filetime::to_micros;
use crate::standard_info::Macb;
use mft::attribute::x30::{FileNameAttr, FileNamespace};

/// The NTFS filename namespace of a `$FILE_NAME` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Namespace {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
}

impl Namespace {
    pub fn from_attr(ns: &FileNamespace) -> Self {
        match ns {
            FileNamespace::POSIX => Namespace::Posix,
            FileNamespace::Win32 => Namespace::Win32,
            FileNamespace::DOS => Namespace::Dos,
            FileNamespace::Win32AndDos => Namespace::Win32AndDos,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Namespace::Posix => "POSIX",
            Namespace::Win32 => "Win32",
            Namespace::Dos => "DOS",
            Namespace::Win32AndDos => "Win32AndDos",
        }
    }

    /// Whether this name is a human-readable long name (Win32 / Win32&DOS), as
    /// opposed to the 8.3 DOS short name or a POSIX name. The timeline path is
    /// built from a long name in preference to a short one.
    pub fn is_long(self) -> bool {
        matches!(self, Namespace::Win32 | Namespace::Win32AndDos)
    }
}

/// A decoded `$FILE_NAME` attribute. A record may carry several (a Win32 long
/// name + its 8.3 DOS short name, plus one per hard link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileName {
    pub name: String,
    pub namespace: Namespace,
    /// Parent directory's MFT entry number.
    pub parent_entry: u64,
    /// Parent's *expected* sequence number (for stale-parent detection, §A.4).
    pub parent_seq: u16,
    pub macb: Macb,
    pub logical_size: u64,
    pub physical_size: u64,
}

impl FileName {
    pub fn from_attr(fna: &FileNameAttr) -> Self {
        FileName {
            name: fna.name.clone(),
            namespace: Namespace::from_attr(&fna.namespace),
            parent_entry: fna.parent.entry,
            parent_seq: fna.parent.sequence,
            macb: Macb {
                created: to_micros(fna.created),
                modified: to_micros(fna.modified),
                accessed: to_micros(fna.accessed),
                mft_modified: to_micros(fna.mft_modified),
            },
            logical_size: fna.logical_size,
            physical_size: fna.physical_size,
        }
    }
}

/// Choose the primary `$FILE_NAME` from a record's list: prefer a long
/// (Win32 / Win32&DOS) name, else fall back to the first available.
pub fn primary_index(names: &[FileName]) -> Option<usize> {
    names
        .iter()
        .position(|n| n.namespace.is_long())
        .or(if names.is_empty() { None } else { Some(0) })
}
