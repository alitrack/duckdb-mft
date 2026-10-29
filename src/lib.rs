// DuckDB loadable extension: NTFS $MFT (Master File Table) record inspection, in SQL.
//
// Thin quack-rs binding over `mft_core` (verbatim from Query-farm's vgi-mft
// mft-core crate, MIT): pure NTFS $MFT record decode + path reconstruction +
// well-formedness triage. Only the Arrow IPC transport was replaced with direct
// C-API vector I/O.
//
// Function surface (v1 — 3 flat scalars, all `(blob, entry)` in):
//
//   mft_record_header(blob, entry) -> STRUCT(signature, sequence, in_use, is_dir,
//                                             base_ref, lsn, used_size, allocated_size)
//   mft_well_formed(blob, entry)   -> STRUCT(ok, error, kind)   never panics
//   mft_full_path(blob, entry)     -> VARCHAR   reconstructed DOS 8.3-style path
//
// `blob` is a `BLOB` holding the raw `$MFT` file bytes (e.g. from a disk-image
// carve, read with DuckDB's `read_blob`). `entry` is the UBIGINT $MFT record
// number to inspect. All three are **total**: an empty / out-of-range /
// unparseable entry yields a NULL result (or `ok=false` for well_formed) —
// never a SQL error, and a corrupt/hole record can't crash the host.
//
// Not ported in v1: the `read_mft` **table** function (one row per $MFT record
// with the full attribute / stream fan-out), the `timestomp` anti-forensic
// heuristic (it takes two STRUCT-of-timestamp quads + returns a LIST of reasons
// — both untested in the quack 0.18 scalar surface), and the table_in_out
// `attributes`/`streams`. See the README.

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::ScalarFunctionBuilder;
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{VectorReader, VectorWriter};

use mft_core::errors::WellFormed;
use mft_core::{full_path as mft_full_path, record_header as mft_record_header, well_formed as mft_well_formed};

/// Read a BLOB cell into bytes; None when the row is NULL/invalid.
unsafe fn payload_bytes(value: &VectorReader, row: usize) -> Option<Vec<u8>> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_blob(row).to_vec())
}

/// Read an unsigned 64-bit entry index; None when NULL/invalid.
unsafe fn entry_idx(value: &VectorReader, row: usize) -> Option<u64> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_u64(row))
}

/// The `record_header` STRUCT layout (must match the callback's writes).
const RECORD_HEADER_FIELDS: &[(&str, TypeId)] = &[
    ("signature", TypeId::Varchar),
    ("sequence", TypeId::USmallInt),
    ("in_use", TypeId::Boolean),
    ("is_dir", TypeId::Boolean),
    ("base_ref", TypeId::UBigInt),
    ("lsn", TypeId::UBigInt),
    ("used_size", TypeId::UInteger),
    ("allocated_size", TypeId::UInteger),
];

/// The `well_formed` STRUCT layout.
const WELL_FORMED_FIELDS: &[(&str, TypeId)] =
    &[("ok", TypeId::Boolean), ("error", TypeId::Varchar), ("kind", TypeId::Varchar)];

// ─────────────────────────────────────────────────────────────────────────────
// mft_record_header(blob, entry) -> STRUCT(8 flat fields)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(record_header_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let entry = VectorReader::new(input, 1);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, RECORD_HEADER_FIELDS.len());
        for row in 0..row_count {
            match (payload_bytes(&blob, row), entry_idx(&entry, row)) {
                (Some(bytes), Some(n)) => match mft_record_header(bytes, n) {
                    Some(h) => {
                        sw.write_varchar(row, 0, &h.signature);
                        sw.write_u16(row, 1, h.sequence);
                        sw.write_bool(row, 2, h.in_use);
                        sw.write_bool(row, 3, h.is_dir);
                        sw.write_u64(row, 4, h.base_ref);
                        sw.write_u64(row, 5, h.lsn);
                        sw.write_u32(row, 6, h.used_size);
                        sw.write_u32(row, 7, h.allocated_size);
                    }
                    None => {
                        for f in 0..RECORD_HEADER_FIELDS.len() {
                            sw.set_null(row, f);
                        }
                    }
                },
                _ => {
                    for f in 0..RECORD_HEADER_FIELDS.len() {
                        sw.set_null(row, f);
                    }
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// mft_well_formed(blob, entry) -> STRUCT(ok, error, kind)   (never panics)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(well_formed_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let entry = VectorReader::new(input, 1);
        let row_count = blob.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, WELL_FORMED_FIELDS.len());
        for row in 0..row_count {
            match (payload_bytes(&blob, row), entry_idx(&entry, row)) {
                (Some(bytes), Some(n)) => {
                    let wf: WellFormed = mft_well_formed(bytes, n);
                    sw.write_bool(row, 0, wf.ok);
                    match &wf.error {
                        Some(e) => sw.write_varchar(row, 1, e),
                        None => sw.set_null(row, 1),
                    }
                    sw.write_varchar(row, 2, wf.kind.as_str());
                }
                _ => {
                    sw.set_null(row, 0);
                    sw.set_null(row, 1);
                    sw.set_null(row, 2);
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// mft_full_path(blob, entry) -> VARCHAR   (NULL for out-of-range / unresolvable)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(full_path_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let entry = VectorReader::new(input, 1);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match (payload_bytes(&blob, row), entry_idx(&entry, row)) {
                (Some(bytes), Some(n)) => {
                    // `full_path` takes a hard depth cap; 256 is far beyond any
                    // realistic NTFS path and bounds the resolver walk on a
                    // hostile (cyclic) $MFT.
                    match mft_full_path(bytes, n, 256).ok().flatten() {
                        Some(p) => writer.write_varchar(row, &p),
                        None => writer.set_null(row),
                    }
                }
                _ => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("mft_record_header")
            .param(TypeId::Blob)
            .param(TypeId::UBigInt)
            .returns_logical(LogicalType::struct_type(RECORD_HEADER_FIELDS))
            .function(record_header_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("mft_well_formed")
            .param(TypeId::Blob)
            .param(TypeId::UBigInt)
            .returns_logical(LogicalType::struct_type(WELL_FORMED_FIELDS))
            .function(well_formed_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("mft_full_path")
            .param(TypeId::Blob)
            .param(TypeId::UBigInt)
            .returns(TypeId::Varchar)
            .function(full_path_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(mft_init_c_api, |con| register_all(con));
