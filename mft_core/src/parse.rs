//! Panic-safe single-record parsing.
//!
//! The underlying `mft` crate is not panic-safe on hostile input — a corrupt
//! first header can make `MftParser` overflow its stride arithmetic, and
//! `apply_fixups` can underflow / slice out of bounds on a mutilated record.
//! Since a `$MFT` collected from a compromised or failing host is exactly that
//! kind of input, every per-record parse here runs inside a `catch_unwind`
//! backstop: a panic becomes a diagnostic, never a crashed scan.

use std::panic::{catch_unwind, AssertUnwindSafe};

use mft::MftEntry;

use crate::errors::{classify_parse_error, WellFormedKind};

/// The outcome of parsing one record buffer.
pub enum ParseOutcome {
    /// An empty (zeroed) slot — not emitted as a row.
    Empty,
    /// A successfully parsed FILE / BAAD record.
    Ok(Box<MftEntry>),
    /// A malformed record, classified.
    Bad(WellFormedKind, String),
}

/// Parse one `record_size`-sized buffer as MFT entry `n`, catching any panic
/// from the underlying parser.
pub fn parse_record(record: Vec<u8>, n: u64) -> ParseOutcome {
    // Zeroed slot: don't even hand it to the parser.
    if record.iter().all(|&b| b == 0) {
        return ParseOutcome::Empty;
    }
    let result = catch_unwind(AssertUnwindSafe(|| MftEntry::from_buffer(record, n)));
    match result {
        Ok(Ok(entry)) => {
            if entry.header.signature == *b"\x00\x00\x00\x00" {
                ParseOutcome::Empty
            } else {
                ParseOutcome::Ok(Box::new(entry))
            }
        }
        Ok(Err(e)) => {
            let (kind, msg) = classify_parse_error(&e);
            ParseOutcome::Bad(kind, msg)
        }
        Err(_) => ParseOutcome::Bad(
            WellFormedKind::AttrOverrun,
            "parser panicked on malformed record (caught)".to_string(),
        ),
    }
}

/// Fully decode a parsed entry, catching any panic from the crate's per-attribute
/// content parse (the attribute walk runs outside [`parse_record`]'s catch). On a
/// caught panic, returns a diagnostic-only record so the scan continues.
pub fn decode_entry_safe(entry: &MftEntry, n: u64, resident_cap: usize) -> crate::DecodedRecord {
    catch_unwind(AssertUnwindSafe(|| {
        crate::record::decode_entry(entry, resident_cap)
    }))
    .unwrap_or_else(|_| {
        crate::record::diagnostic_record(n, "attr-overrun:decode panicked (caught)")
    })
}

/// Install a process-wide panic hook that silences panics originating inside the
/// third-party parsing crates (`mft`, `winstructs`, `jiff`) — which we already
/// catch via [`parse_record`] — while forwarding all other panics (real bugs) to
/// the default hook. Idempotent-friendly; call once at worker startup.
pub fn quiet_parser_panics() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(loc) = info.location() {
            let f = loc.file();
            if f.contains("/mft-") || f.contains("/winstructs-") || f.contains("/jiff-") {
                return; // caught upstream; suppress the noise
            }
        }
        default(info);
    }));
}
