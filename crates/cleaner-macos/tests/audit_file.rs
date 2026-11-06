//! `FileAuditSink` on a real (temporary) directory: spec 001 AC-001-12 (INV-11, INV-13).
//! All paths are inside `tempfile::TempDir`; the real home is never touched (INV-15).
//!
//! # Worksheet - `FileAuditSink::open` / `AuditSink::write_line`
//! ```text
//! Function:        cleaner_macos::FileAuditSink::open(dir, clock) + write_line(line)
//! Contract:        creates dir (missing parents too) with mode 0700 and the day file
//!                  `audit-YYYY-MM-DD.jsonl` (name from the clock) with mode 0600 AT OPEN; appends
//!                  `line` + "\n" and flushes before returning; never truncates; O_APPEND so two
//!                  writers never overwrite each other; any failure to create/open ->
//!                  Err(AuditError::Unavailable). (AC-001-12, INV-11, INV-13)
//! Equivalence classes: fresh dir | pre-existing file | second writer on same file |
//!                  dir not creatable | file not openable
//! Boundaries:      first write vs later writes; content visible while sink still open
//! Must-never:      truncate existing log; world/group-readable log; buffered-but-unflushed record;
//!                  panic when the location is unusable
//! Selected tests:  see fns below
//! Deliberately not tested: fsync (INV-11 requires it only for destructive tiers, phase 2);
//!                  tightening the mode of a PRE-EXISTING directory (unspecified, see matrix);
//!                  day rollover mid-run (file fixed at open, see matrix).
//! Hardening round: `path()` returns the file opened (fixed at `open`), so the CLI prints the file
//!                  really written; selected test `ac_002_17_sink_reports_the_exact_path_...`.
//! ```

use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cleaner_core::audit::{AuditError, AuditSink, audit_file_name};
use cleaner_core::ports::Clock;
use cleaner_macos::FileAuditSink;
use cleaner_testkit::FixedClock;

/// Clock fixed at 2026-11-06T12:34:56Z; the day file is `audit-2026-11-06.jsonl`.
fn clock() -> FixedClock {
    FixedClock::at_utc(2026, 11, 6, 12, 34, 56)
}

/// Permission bits (`& 0o777`) of `path`.
fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// # Design promise
/// AC-001-12 / INV-11, INV-16: the audit directory is private (0700), the audit file is private
/// (0600), and both exist as soon as the sink is open (so unusability is detected up front).
///
/// # Scenario (Given)
/// A temp dir; the log dir `<tmp>/Library/Logs/mac-cleaner` and its parents do not exist.
///
/// # Action (When)
/// `FileAuditSink::open(dir, clock)`.
///
/// # Expected (Then)
/// `Ok`; the leaf dir has mode 0700; it contains exactly one entry, named from the clock
/// (`audit-2026-11-06.jsonl`), with mode 0600.
///
/// # Must never
/// Create a group/world-readable log (paths and sizes are private, INV-16).
///
/// # Would catch
/// `create_dir_all` / `File::create` with default umask-derived modes (0755/0644).
///
/// # Why this test (not redundant)
/// The only permissions/creation test; durability and append semantics are the next two.
#[test]
fn ac_001_12_open_creates_private_dir_0700_and_private_file_0600() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path().join("Library/Logs/mac-cleaner");

    // Act
    let sink = FileAuditSink::open(&dir, &clock());

    // Assert
    assert!(
        sink.is_ok(),
        "open must succeed on a creatable location, got {sink:?}"
    );
    assert!(
        dir.is_dir(),
        "the log directory must be created (with missing parents)"
    );
    assert_eq!(mode(&dir), 0o700, "INV-16: log directory must be 0700");
    let entries: Vec<_> = fs::read_dir(&dir)
        .expect("list dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(
        entries,
        vec![std::ffi::OsString::from(audit_file_name(clock().now()))],
        "exactly the day file"
    );
    assert_eq!(
        mode(&dir.join("audit-2026-11-06.jsonl")),
        0o600,
        "INV-16: audit file must be 0600"
    );
}

/// # Design promise
/// AC-001-12 / INV-11: a record is on its way to the OS before `write_line` returns - it is not
/// held in a user-space buffer - and lines are newline-terminated, in order.
///
/// # Scenario (Given)
/// An open sink (kept alive for the whole test, never dropped/closed early).
///
/// # Action (When)
/// `write_line` two lines, reading the file through a separate handle after each call.
///
/// # Expected (Then)
/// After the first call the file content is exactly `first\n`; after the second, `first\nsecond\n`.
///
/// # Must never
/// Defer a record to `Drop`/close (a crash would lose the evidence).
///
/// # Would catch
/// A `BufWriter` without per-record flush.
///
/// # Why this test (not redundant)
/// Only flush-per-record coverage.
#[test]
fn ac_001_12_each_record_is_flushed_before_write_line_returns() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path().join("logs");
    let file = dir.join("audit-2026-11-06.jsonl");
    let mut sink = FileAuditSink::open(&dir, &clock()).expect("open");

    // Act + Assert
    sink.write_line(r#"{"n":1}"#).expect("first write");
    assert_eq!(
        fs::read_to_string(&file).unwrap_or_default(),
        "{\"n\":1}\n",
        "first record must be visible at once"
    );
    sink.write_line(r#"{"n":2}"#).expect("second write");
    assert_eq!(
        fs::read_to_string(&file).unwrap_or_default(),
        "{\"n\":1}\n{\"n\":2}\n",
        "second record must be visible at once and appended in order"
    );
}

/// # Design promise
/// AC-001-12: existing logs are appended to, never truncated, and the file is opened append-only so
/// even two live writers cannot overwrite each other.
///
/// # Scenario (Given)
/// `audit-2026-11-06.jsonl` already holds `old line\n`; sink A opens it, then sink B opens the same
/// file while A is still alive.
///
/// # Action (When)
/// A writes `a1`, B writes `b1`, A writes `a2`.
///
/// # Expected (Then)
/// File content is `old line\na1\nb1\na2\n`.
///
/// # Must never
/// Truncate on open; write at a stale offset and clobber the other writer's record.
///
/// # Would catch
/// `OpenOptions::truncate(true)` / `File::create`, or `write(true)` without `append(true)`.
///
/// # Why this test (not redundant)
/// Only coverage of append-only/non-truncating semantics.
#[test]
fn ac_001_12_existing_log_is_appended_to_never_truncated_even_with_two_writers() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path().join("logs");
    fs::create_dir_all(&dir).expect("mkdir");
    let file = dir.join("audit-2026-11-06.jsonl");
    File::create(&file)
        .and_then(|mut f| f.write_all(b"old line\n"))
        .expect("seed existing log");
    let mut a = FileAuditSink::open(&dir, &clock()).expect("open A");
    let mut b = FileAuditSink::open(&dir, &clock()).expect("open B");

    // Act
    a.write_line("a1").expect("a1");
    b.write_line("b1").expect("b1");
    a.write_line("a2").expect("a2");

    // Assert
    assert_eq!(
        fs::read_to_string(&file).unwrap_or_default(),
        "old line\na1\nb1\na2\n",
        "existing content kept and writers interleave without overwriting"
    );
}

/// # Design promise
/// AC-001-12 / INV-13: when the log location cannot be used, constructing the sink returns
/// `Err(AuditError::Unavailable)` (never panics, never pretends).
///
/// # Scenario (Given)
/// Row 1: the would-be log dir lives *below a regular file* (cannot be created). Row 2: the dir
/// exists but a *directory* occupies the day file's name (cannot be opened as a file). Both are
/// failures even for root, so the test is deterministic.
///
/// # Action (When)
/// `FileAuditSink::open` for each.
///
/// # Expected (Then)
/// Both `Err(AuditError::Unavailable { .. })`.
///
/// # Must never
/// Return `Ok` (a mutating phase would then run unaudited, violating INV-11/13); panic.
///
/// # Would catch
/// `.ok()`/`unwrap_or_default` swallowing the error; mapping failures to `Io`.
///
/// # Why this test (not redundant)
/// Only unavailable-sink coverage; the callers' policy is tested in spec 002.
#[test]
fn ac_001_12_unusable_location_is_reported_as_unavailable() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let blocker = tmp.path().join("blocker");
    File::create(&blocker)
        .and_then(|mut f| f.write_all(b"x"))
        .expect("regular file");
    let dir_with_dir_as_file = tmp.path().join("logs2");
    fs::create_dir_all(dir_with_dir_as_file.join("audit-2026-11-06.jsonl"))
        .expect("dir named like the log file");
    let cases = [
        ("parent-is-a-file", blocker.join("logs")),
        ("file-name-is-a-dir", dir_with_dir_as_file),
    ];

    for (name, dir) in cases {
        // Act
        let got = FileAuditSink::open(&dir, &clock());

        // Assert
        assert!(
            matches!(got, Err(AuditError::Unavailable { .. })),
            "case `{name}`: expected Err(Unavailable), got {got:?}"
        );
    }
}

/// # Design promise
/// Hardening round (extends AC-001-12 / AC-002-17, INV-11): the sink reports the exact path it
/// opened, fixed at `open` from the clock it was given. A caller that prints "Audit log: <path>"
/// must print the file that is really being written, even when the wall clock later crosses UTC
/// midnight (re-deriving the name from a second `now()` call would name the wrong day).
///
/// # Scenario (Given)
/// A temp dir and a clock fixed at 2026-12-31T23:59:59Z (the last second of a day, so a name
/// computed one second later would differ: the interesting boundary for the bug), a log dir that
/// does not exist yet.
///
/// # Action (When)
/// `FileAuditSink::open(dir, clock)`, then `sink.path()`, then one `write_line`.
///
/// # Expected (Then)
/// `path()` equals `<dir>/audit-2026-12-31.jsonl` exactly (not canonicalized, not relative); a regular
/// file exists at that path; the line written through the sink is the content of that very file.
///
/// # Must never
/// Report a path other than the file the sink writes to (the user would inspect the wrong log);
/// report a path for a file that was not created.
///
/// # Would catch
/// A `path()` that recomputes the name from the clock, returns the directory, a placeholder or a
/// canonicalized variant, or a sink whose reported path and opened file diverge.
///
/// # Why this test (not redundant)
/// The only test of the sink's reported path; the creation test above asserts the directory listing
/// and modes but never calls `path()`, and the CLI test checks the printed line end to end.
#[test]
fn ac_002_17_sink_reports_the_exact_path_it_opened_fixed_at_open() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path().join("logs");
    let clock = FixedClock::at_utc(2026, 12, 31, 23, 59, 59);
    let mut sink = FileAuditSink::open(&dir, &clock).expect("open");

    // Act
    let reported = sink.path().to_path_buf();
    sink.write_line("probe").expect("write through the sink");

    // Assert
    assert_eq!(
        reported,
        dir.join("audit-2026-12-31.jsonl"),
        "the sink must report <dir>/audit-<day of the clock at open>.jsonl"
    );
    assert!(
        reported.is_file(),
        "a regular file must exist at the reported path {}",
        reported.display()
    );
    assert_eq!(
        fs::read_to_string(&reported).unwrap_or_default(),
        "probe\n",
        "the reported path must be the file the sink actually writes to"
    );
}
