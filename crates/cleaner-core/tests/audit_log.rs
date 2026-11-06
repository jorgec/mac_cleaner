//! Audit record encoding (spec 001 AC-001-11, AC-001-13; INV-11, INV-16). The file sink's
//! durability/permissions (AC-001-12) are tested in `cleaner-macos/tests/audit_file.rs`;
//! retention/naming (AC-001-14) in `audit_retention.rs`.
//!
//! # Worksheet - `AuditLog::record` + `audit::decode_line`
//! ```text
//! Function:        AuditLog::new(sink, clock, run_id).record(&Record); decode_line(&str)
//! Contract:        each record -> exactly one JSON line: schema=1, ts (RFC 3339 UTC seconds, `Z`,
//!                  from the injected clock at record time; pre-epoch clamps to epoch), run_id,
//!                  seq (1,2,3.. gap-free, not advanced by a failed write), kind (snake_case);
//!                  no raw `\n`/`\r` in the line; path fields = `path` (lossy) + `path_b64`
//!                  (std base64, padded) only when lossy != original; decode ignores unknown
//!                  fields and reconstructs paths losslessly. (AC-001-11, AC-001-13)
//! Equivalence classes: envelope of all four kinds | newline-bearing path | unknown future field
//!                  | failed write | pre-epoch clock | UTF-8 path | non-UTF-8 path
//! Boundaries:      seq 1 (first) and +1 steps; failed write then success; UTF-8 vs non-UTF-8 path
//! Must-never:      a raw newline in a line; a seq gap; `path_b64` on a clean UTF-8 path; loss of
//!                  non-UTF-8 bytes; panic on a pre-epoch clock
//! Selected tests:  see fns below
//! Deliberately not tested: field names of non-path payload (round-trip through decode instead of
//!                  asserting names, spec 002 extends them); serde derive behavior; the reserved
//!                  phase-2 variants (do not exist yet).
//! ```

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use cleaner_core::audit::{AuditLog, Record, ScanCounts, decode_line};
use cleaner_core::ports::RunIds;
use cleaner_testkit::{FixedClock, MemorySink, SequentialRunIds};
use serde_json::{Value, json};

/// A log writing into a shared `MemorySink`, clock frozen at 2026-11-06T12:34:56Z, run id `RUN-0001`.
fn fixture() -> (AuditLog, MemorySink, Arc<FixedClock>) {
    let sink = MemorySink::new();
    let clock = Arc::new(FixedClock::at_utc(2026, 11, 6, 12, 34, 56));
    let run_id = SequentialRunIds::new().next_run_id();
    (
        AuditLog::new(Box::new(sink.clone()), clock.clone(), run_id),
        sink,
        clock,
    )
}

/// Parse a written line as a JSON object, failing the test with the line on error.
fn parse(line: &str) -> Value {
    let v: Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("not valid JSON ({e}): {line}"));
    assert!(v.is_object(), "an audit line must be a JSON object: {line}");
    v
}

/// The single line a test expects the sink to hold; fails with a clear message if nothing (or more
/// than one line) was written.
fn only_line(sink: &MemorySink) -> String {
    let lines = sink.lines();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one audit line, got {lines:?}"
    );
    lines.into_iter().next().unwrap_or_default()
}

/// A `Skipped` record for `path`.
fn skipped(path: impl Into<PathBuf>) -> Record {
    Record::Skipped {
        path: path.into(),
        reason: "permission_denied".to_owned(),
    }
}

/// # Design promise
/// AC-001-11 / INV-11: every record is one valid JSON line carrying `schema:1`, a `ts` from the
/// injected clock (at record time), the run's `run_id`, a gap-free 1-based `seq`, and its `kind`.
///
/// # Scenario (Given)
/// A log over an in-memory sink; clock at 2026-11-06T12:34:56Z advanced by 1 s before each of the
/// four phase-1 record kinds (`run_start`, `scan_result`, `skipped`, `run_end`).
///
/// # Action (When)
/// `record()` the four records in order.
///
/// # Expected (Then)
/// 4 lines; each has no `\n`/`\r`, parses to an object with `schema == 1`, `run_id == "RUN-0001"`,
/// `seq == 1..=4`, `kind` == `snake_case` of the variant, and `ts` == the clock's UTC instant
/// (`...:56Z`, `:57Z`, `:58Z`, `:59Z`: per-record, not frozen at construction). `decode_line` of
/// every line returns the original record (all four kinds, including `u64::MAX` bytes and a
/// non-zero exit code with `interrupted: true`) with the same `schema`, `ts`, `run_id` and `seq`.
///
/// # Must never
/// Emit a multi-line record, skip or repeat a `seq`, read the system clock; lose or mis-map a field
/// of any record kind on read (a reader that drops `bytes`, swaps `items`, or defaults a field).
///
/// # Would catch
/// `ts` captured once in `new()`, `seq` starting at 0, a shared counter per kind, pretty-printed JSON;
/// a decoder that handles only some kinds, truncates large integers via `f64`, or ignores fields.
///
/// # Why this test (not redundant)
/// The only envelope test and the only decode coverage of `run_start`/`scan_result`; newline escaping,
/// failed writes and the epoch are separate classes.
#[test]
fn ac_001_11_every_record_is_one_json_line_with_gapless_seq_and_clock_stamped_ts() {
    // Arrange
    let (mut log, sink, clock) = fixture();
    let records = [
        Record::RunStart {
            argv: vec!["cleaner".to_owned(), "scan".to_owned()],
            rule_ids: vec!["user-caches".to_owned()],
            version: "0.0.0".to_owned(),
            home: PathBuf::from("/Users/u"),
        },
        Record::ScanResult {
            rule_id: "user-caches".to_owned(),
            status: "ok".to_owned(),
            bytes: u64::MAX,
            items: 3,
            // Non-zero, distinct values so a decoder that mixes up or drops a counter is caught
            // (spec 002 extension of the record).
            counts: ScanCounts {
                logical_bytes: u64::MAX - 1,
                skipped: 5,
                skipped_unlogged: 2,
                vanished: 7,
                deduped_links: 11,
            },
        },
        skipped("/Users/u/Library/Caches/x"),
        Record::RunEnd {
            exit_code: 130,
            interrupted: true,
            total_bytes: u64::MAX,
            total_items: 13,
        },
    ];
    let kinds = ["run_start", "scan_result", "skipped", "run_end"];

    // Act
    for r in &records {
        log.record(r).expect("memory sink never fails");
        clock.advance_secs(1);
    }

    // Assert
    let lines = sink.lines();
    assert_eq!(lines.len(), 4, "exactly one line per record");
    for (i, line) in lines.iter().enumerate() {
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "line {i} contains a raw newline: {line:?}"
        );
        let v = parse(line);
        assert_eq!(v["schema"], json!(1), "line {i}: schema must be 1");
        assert_eq!(
            v["run_id"],
            json!("RUN-0001"),
            "line {i}: run_id must be the run's id"
        );
        assert_eq!(
            v["seq"],
            json!(i + 1),
            "line {i}: seq must be 1-based and gap-free"
        );
        assert_eq!(
            v["kind"],
            json!(kinds[i]),
            "line {i}: kind must be the snake_case variant name"
        );
        assert_eq!(
            v["ts"],
            json!(format!("2026-11-06T12:34:{}Z", 56 + i)),
            "line {i}: ts must come from the clock at record time"
        );
        let decoded = decode_line(line).unwrap_or_else(|e| panic!("line {i} must decode: {e:?}"));
        assert_eq!(
            decoded.record, records[i],
            "line {i}: decode must reproduce the {} record",
            kinds[i]
        );
        assert_eq!(
            (decoded.schema, decoded.seq, decoded.run_id.as_str()),
            (1, (i + 1) as u64, "RUN-0001"),
            "line {i}: decoded envelope"
        );
        assert_eq!(
            decoded.ts,
            format!("2026-11-06T12:34:{}Z", 56 + i),
            "line {i}: decoded ts"
        );
    }
}

/// # Design promise
/// AC-001-11: embedded newlines (and other control/quote characters) in a path are escaped by JSON,
/// so a record is always exactly one line, and decoding gives the original path back.
///
/// # Scenario (Given)
/// A `Skipped` record whose path is `/tmp/a\nb\rc"d\\e` (newline, CR, quote, backslash).
///
/// # Action (When)
/// `record()` it, then `decode_line` the written line.
///
/// # Expected (Then)
/// One line without raw `\n`/`\r`; the JSON `path` field equals the original text; the decoded
/// record equals the input and decoded `seq == 1`, `run_id == RUN-0001`.
///
/// # Must never
/// Let a path inject a line break (log forging: a fake second record).
///
/// # Would catch
/// Hand-built JSON strings without escaping; writing `path` via `Display` instead of JSON.
///
/// # Why this test (not redundant)
/// Hostile-name class of the envelope test, plus the encode->decode round trip.
#[test]
fn ac_001_11_embedded_newline_in_a_path_stays_on_one_line_and_round_trips() {
    // Arrange
    let (mut log, sink, _clock) = fixture();
    let original = skipped("/tmp/a\nb\rc\"d\\e");

    // Act
    log.record(&original).expect("memory sink never fails");

    // Assert
    let lines = sink.lines();
    assert_eq!(
        lines.len(),
        1,
        "a path with newlines must not split the record"
    );
    assert!(
        !lines[0].contains('\n') && !lines[0].contains('\r'),
        "raw control char in line: {:?}",
        lines[0]
    );
    assert_eq!(
        parse(&lines[0])["path"],
        json!("/tmp/a\nb\rc\"d\\e"),
        "path must survive JSON escaping"
    );
    let decoded = decode_line(&lines[0]).expect("our own line must decode");
    assert_eq!(
        decoded.record, original,
        "round trip must reproduce the record"
    );
    assert_eq!(
        (decoded.seq, decoded.run_id.as_str()),
        (1, "RUN-0001"),
        "envelope must round-trip"
    );
}

/// # Design promise
/// AC-001-11: readers tolerate unknown future fields (forward compatibility of schema 1).
///
/// # Scenario (Given)
/// A line produced by `record()` for a `RunEnd`, with extra top-level fields `future_field` (object)
/// and `another` (array) injected.
///
/// # Action (When)
/// `decode_line` on the augmented line.
///
/// # Expected (Then)
/// `Ok`, with the same record, `seq`, `run_id` and `schema` as the original.
///
/// # Must never
/// Reject a newer writer's extra fields (would make `undo`/readers brittle across versions).
///
/// # Would catch
/// `#[serde(deny_unknown_fields)]`.
///
/// # Why this test (not redundant)
/// Only forward-compat coverage of the reader.
#[test]
fn ac_001_11_decode_tolerates_unknown_future_fields() {
    // Arrange
    let (mut log, sink, _clock) = fixture();
    let original = Record::RunEnd {
        exit_code: 4,
        interrupted: true,
        total_bytes: 0,
        total_items: 0,
    };
    log.record(&original).expect("memory sink never fails");
    let mut v = parse(&only_line(&sink));
    v["future_field"] = json!({"a": [1, 2, 3]});
    v["another"] = json!(["x"]);

    // Act
    let decoded = decode_line(&v.to_string()).expect("unknown fields must be ignored");

    // Assert
    assert_eq!(
        decoded.record, original,
        "known payload must be unchanged by extra fields"
    );
    assert_eq!(
        (decoded.schema, decoded.seq),
        (1, 1),
        "envelope must be unchanged by extra fields"
    );
}

/// # Design promise
/// AC-001-11 ("strictly +1, no gaps"): a record that failed to reach the sink does not consume a
/// `seq`, so the written log never shows a gap. (Spec is silent on failure; this is the reading
/// that keeps the promise true - flagged for ratification.)
///
/// # Scenario (Given)
/// A sink that fails exactly the next write.
///
/// # Action (When)
/// `record()` twice.
///
/// # Expected (Then)
/// First call `Err`; second `Ok`; exactly one line, with `seq == 1`.
///
/// # Must never
/// Leave a hole in `seq` after a failed append (it would look like a deleted record).
///
/// # Would catch
/// Incrementing `seq` before the write succeeds.
///
/// # Why this test (not redundant)
/// Only failure-path coverage of `seq`.
#[test]
fn ac_001_11_seq_does_not_advance_when_the_write_fails() {
    // Arrange
    let (mut log, sink, _clock) = fixture();
    sink.fail_next_writes(1);

    // Act
    let first = log.record(&skipped("/a"));
    let second = log.record(&skipped("/b"));

    // Assert
    assert!(
        first.is_err(),
        "the injected failure must surface to the caller"
    );
    assert!(second.is_ok(), "the next write succeeds");
    let lines = sink.lines();
    assert_eq!(lines.len(), 1, "only the successful record is stored");
    assert_eq!(
        parse(&lines[0])["seq"],
        json!(1),
        "seq must not skip over the failed record"
    );
}

/// # Design promise
/// Spec 001 failure modes: a clock before the Unix epoch still formats (clamped to the epoch) and
/// never panics.
///
/// # Scenario (Given)
/// A clock 5 seconds before 1970-01-01T00:00:00Z.
///
/// # Action (When)
/// `record()` any record.
///
/// # Expected (Then)
/// `Ok`; `ts == "1970-01-01T00:00:00Z"`.
///
/// # Must never
/// Panic (`duration_since(UNIX_EPOCH).unwrap()`), underflow, or emit a negative/garbled timestamp.
///
/// # Would catch
/// `SystemTime::duration_since(..).unwrap()`.
///
/// # Why this test (not redundant)
/// The only pre-epoch boundary of the timestamp formatter.
#[test]
fn ac_001_11_pre_epoch_clock_is_clamped_and_never_panics() {
    // Arrange
    let sink = MemorySink::new();
    let clock = Arc::new(FixedClock::from_unix_secs(-5));
    let mut log = AuditLog::new(
        Box::new(sink.clone()),
        clock,
        SequentialRunIds::new().next_run_id(),
    );

    // Act
    let result = log.record(&Record::RunEnd {
        exit_code: 0,
        interrupted: false,
        total_bytes: 0,
        total_items: 0,
    });

    // Assert
    assert!(result.is_ok(), "a pre-epoch clock must not fail the write");
    assert_eq!(
        parse(&only_line(&sink))["ts"],
        json!("1970-01-01T00:00:00Z"),
        "pre-epoch must clamp to the epoch"
    );
}

/// # Design promise
/// AC-001-13 / INV-16: paths are recorded losslessly. A UTF-8 path appears once as `path`; a path
/// with non-UTF-8 bytes appears as a lossy `path` plus `path_b64` (standard padded base64 of the raw
/// bytes), and decoding restores the exact bytes.
///
/// # Scenario (Given)
/// Rows: `/tmp/plain` (UTF-8) and the byte path `/tmp/\xFF\xFEz` (invalid UTF-8).
///
/// # Action (When)
/// `record(Skipped{path})` for each, then `decode_line`.
///
/// # Expected (Then)
/// UTF-8: `path` equals the text and the `path_b64` key is **absent**. Non-UTF-8: `path` equals
/// `to_string_lossy()` (contains U+FFFD); `path_b64`, decoded independently with the `base64`
/// crate, equals the raw bytes; `decode_line` returns the identical byte path in both rows.
///
/// # Must never
/// Drop or replace bytes irrecoverably; add `path_b64` when it is redundant.
///
/// # Would catch
/// `to_string_lossy()` only; always emitting `path_b64`; URL-safe/unpadded alphabet; decode ignoring
/// `path_b64`.
///
/// # Why this test (not redundant)
/// The only coverage of path fidelity; envelope tests use clean paths.
#[test]
fn ac_001_13_non_utf8_paths_are_recorded_losslessly_and_utf8_paths_are_not_duplicated() {
    // Arrange
    let raw: Vec<u8> = [b"/tmp/".as_slice(), &[0xFF, 0xFE], b"z"].concat();
    let rows = [
        ("utf8", PathBuf::from("/tmp/plain"), None),
        (
            "non-utf8",
            PathBuf::from(OsString::from_vec(raw.clone())),
            Some(raw),
        ),
    ];

    for (name, path, raw_bytes) in rows {
        let (mut log, sink, _clock) = fixture();

        // Act
        log.record(&skipped(path.clone()))
            .expect("memory sink never fails");

        // Assert
        let line = only_line(&sink);
        let v = parse(&line);
        assert_eq!(
            v["path"],
            json!(path.to_string_lossy()),
            "row `{name}`: `path` is the lossy text"
        );
        match raw_bytes {
            None => assert!(
                v.get("path_b64").is_none(),
                "row `{name}`: path_b64 only when lossy differs"
            ),
            Some(bytes) => {
                let b64 = v["path_b64"]
                    .as_str()
                    .unwrap_or_else(|| panic!("row `{name}`: path_b64 missing"));
                let back = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .expect("standard padded base64");
                assert_eq!(
                    back, bytes,
                    "row `{name}`: path_b64 must carry the raw bytes"
                );
            }
        }
        let decoded = decode_line(&line).expect("own line decodes");
        assert_eq!(
            decoded.record,
            skipped(path),
            "row `{name}`: decode must restore the exact path"
        );
    }
}
