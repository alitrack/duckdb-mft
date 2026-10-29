# duckdb-mft

**NTFS $MFT inspection, in SQL.** Point the extension at the raw `$MFT` file
bytes (carved from a disk image, read with DuckDB's `read_blob`) and an $MFT
record number, and get back the record header, a well-formedness triage, or the
reconstructed file path — right in DuckDB. No `MFTViewer`, no `pytsk3`, no
Python.

```sql
LOAD 'mft.duckdb_extension';

-- How many $MFT records does the file hold, and is entry #12 a directory?
SELECT h.signature, h.is_dir, h.in_use, h.sequence
FROM (SELECT mft_record_header(content, 12) AS h FROM read_blob('C:\carve\$MFT'));

-- Triage a suspect record
SELECT w.ok, w.kind, w.error
FROM (SELECT mft_well_formed(content, 20) AS w FROM read_blob('C:\carve\$MFT'));

-- Reconstruct the full path for an $MFT entry
SELECT mft_full_path(content, 40) AS path
FROM read_blob('C:\carve\$MFT');
```

## Why

The $MFT (Master File Table) is the NTFS file-system's heart — every file's
metadata (timestamps, size, stream layout, the path it lives at) is in it. The
first things a DFIR analyst or a file-system parser do with a carved `$MFT` are
establish *what an entry is* (header signature, in-use, directory?), *whether it
is parseable*, and *what path it names*. Today that's a round-trip to
`MFTViewer` / `pytsk3` / a script, then a join back. This extension makes those
inspection primitives SQL functions: the `$MFT` is a `BLOB` column, the answers
are values you can `WHERE`, `GROUP BY`, or fan out over a table of carved
records.

## Functions

| Function | Returns | Notes |
|---|---|---|
| `mft_record_header(blob, entry)` | `STRUCT(signature, sequence, in_use, is_dir, base_ref, lsn, used_size, allocated_size)` | Header-only probe of $MFT record `entry` — no attribute decode. `NULL` struct for an empty / out-of-range / unparseable slot. |
| `mft_well_formed(blob, entry)` | `STRUCT(ok, error, kind)` | Validate $MFT record `entry`. `ok` is a boolean, `kind` a category (e.g. `truncated`, `bad-signature`, `ok`), `error` a human string when `ok` is false. **Never panics** — a corrupt / hostile record returns `ok=false`. `NULL` struct for a NULL input. |
| `mft_full_path(blob, entry)` | `VARCHAR` | Reconstruct the file path named by $MFT record `entry` by walking the `$FILE_NAME` parent links up to the root. `NULL` for an out-of-range entry or a path that can't be resolved. |

`blob` is a `BLOB` holding the raw `$MFT` bytes (read with `read_blob('...')`);
`entry` is a `UBIGINT` $MFT record number. All three are **total**: an empty /
out-of-range / unparseable entry yields `NULL` (or `ok=false` for
`mft_well_formed`) — never a SQL error, and a corrupt record cannot crash the
host.

## Scope (v1)

- **The three flat `(blob, entry)` inspection scalars** (verbatim port of the
  `record_header` / `well_formed` / `full_path` free functions from
  Query-farm's `vgi-mft` `mft-core` crate, MIT).
- **Not ported:** the `read_mft` **table** function (one row per $MFT record,
  with the full attribute / data-stream fan-out), the `timestomp` anti-forensic
  heuristic (it takes two STRUCT-of-timestamp quads and returns a LIST of
  reasons — both untested in the quack 0.18 scalar surface), and the
  table_in_out `attributes` / `streams`. Those are the natural v2.

## Build

```sh
make release        # -> target/release/mft.duckdb_extension
make test           # bundled DuckDB runs tests/integration.rs (SQL-level)
```

The cdylib links the DuckDB C extension ABI (resolved at `LOAD` time) plus
`mft_core` (pure Rust over the `mft` parser crate — no I/O, no network, no
Arrow). `panic = "unwind"` keeps a bug in the extension from aborting the host
process.
