//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (3 scalars).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped to
//! `target/release/mft.duckdb_extension`).
//!
//! The `$MFT` under test is the committed `test/data/sample.mft` fixture, read
//! with DuckDB's `read_blob` table function. Expected values are the ground
//! truth from vgi-mft's own `test/sql/scalars.test` (the same fixture, same
//! entry indices): entry 20 → `Windows\System32\cmd.exe`, entry 12 →
//! (signature `FILE`, is_dir true, sequence 1), entry 20 → well-formed ok.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/mft.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display()))
        .expect("load extension");
    d
}

/// `FROM read_blob('<fixture>')` so `content` is the raw $MFT BLOB column.
fn from_fixture() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test/data/sample.mft");
    format!("FROM read_blob('{}')", p.to_string_lossy())
}

#[test]
fn full_path_entry_20() {
    let d = db();
    let fx = from_fixture();
    let path: Option<String> = d
        .query_one(&format!("SELECT mft_full_path(content, 20) {fx}"))
        .unwrap();
    // Ground truth from vgi-mft scalars.test (a plain VARCHAR: no JSON wrapping).
    assert_eq!(path.as_deref(), Some("Windows\\System32\\cmd.exe"));
}

#[test]
fn record_header_entry_12() {
    let d = db();
    let fx = from_fixture();
    let sig: String = d
        .query_one(&format!(
            "SELECT CAST(mft_record_header(content, 12) -> 'signature' AS VARCHAR) {fx}"
        ))
        .unwrap();
    // v1.1.0 struct `->` yields a JSON value; a string child renders WITH its
    // JSON quotes, so the VARCHAR is the 6-char literal `"FILE"`.
    assert_eq!(sig, "\"FILE\"");

    let is_dir: bool = d
        .query_one(&format!(
            "SELECT CAST(mft_record_header(content, 12) -> 'is_dir' AS BOOLEAN) {fx}"
        ))
        .unwrap();
    assert!(is_dir);

    let sequence: i32 = d
        .query_one(&format!(
            "SELECT CAST(mft_record_header(content, 12) -> 'sequence' AS INTEGER) {fx}"
        ))
        .unwrap();
    assert_eq!(sequence, 1);
}

#[test]
fn well_formed_entry_20_ok() {
    let d = db();
    let fx = from_fixture();
    let ok: bool = d
        .query_one(&format!(
            "SELECT CAST(mft_well_formed(content, 20) -> 'ok' AS BOOLEAN) {fx}"
        ))
        .unwrap();
    assert!(ok);
    let kind: String = d
        .query_one(&format!(
            "SELECT CAST(mft_well_formed(content, 20) -> 'kind' AS VARCHAR) {fx}"
        ))
        .unwrap();
    // JSON-rendered string child: the literal `"ok"` (with quotes).
    assert_eq!(kind, "\"ok\"");
}

#[test]
fn total_on_garbage() {
    let d = db();
    // A non-$MFT blob must not produce a parseable header / path. The header
    // signature child is NULL for a garbage slot -> JSON `null` (no quotes).
    let sig: Option<String> = d
        .query_one("SELECT CAST(mft_record_header('not an mft file', 0) -> 'signature' AS VARCHAR)")
        .unwrap();
    assert!(sig.is_none() || sig.as_deref() == Some("null"));

    let path: Option<String> = d
        .query_one("SELECT mft_full_path('not an mft file', 0)")
        .unwrap();
    assert!(path.is_none());
}
