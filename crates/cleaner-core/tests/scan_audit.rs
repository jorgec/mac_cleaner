//! Audit emission, read-only guarantee and cancellation of the scan (spec 002 AC-002-15, AC-002-17,
//! AC-002-18; INV-01, INV-10, INV-11, INV-13).
//!
//! # Worksheet - `scan::run_scan` (lifecycle part)
//! ```text
//! Function:        scan::run_scan(ports, opts, cancel, audit: Option<&mut AuditLog>) -> ScanReport
//! Contract:        audit records of one run, same run_id, gap-free seq: first `run_start` (argv,
//!                  rule ids in order, version, home), one `scan_result` per rule in rule order
//!                  (status, bytes, items, logical/skipped/skipped_unlogged/vanished/deduped counts),
//!                  `skipped` records between them (at most 1000 per run, overflow counted per rule in
//!                  `skipped_unlogged`), last `run_end` (exit code of the report, totals, interrupted);
//!                  a missing or failing audit sink never stops the scan: report.audit_unavailable and
//!                  exit 4; the scan never mutates the filesystem and runs exactly one read-only
//!                  command; a cancelled token stops directory listing, the report is incomplete +
//!                  interrupted (exit 130) and `run_end` still says interrupted. (AC-002-15/17/18)
//! Equivalence classes: full run (ok + partial + absent rules) | skip volume 1000 / 1001 / spread
//!                  over two rules | sink None / sink failing / sink healthy | token pre-cancelled |
//!                  token cancelled mid-walk
//! Boundaries:      1000 vs 1001 skipped; cancel observed before the next listing
//! Must-never:      a seq gap; a skipped record beyond the cap; abort because the log is unavailable;
//!                  list a directory after cancellation; any filesystem change; a second command
//! Selected tests:  see fns below
//! Deliberately not tested: the file sink and its permissions (spec 001), SIGINT delivery and the
//!                  process exit code (CLI, slice 002b), ordering of `skipped` relative to the same
//!                  rule's `scan_result` (the spec does not fix it).
//! ```

mod common;

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use cleaner_core::audit::Record;
use cleaner_core::cancel::CancelToken;
use cleaner_core::ports::{DirEntry, Fs, Metadata};
use cleaner_core::rules::{Rule, Tier};
use cleaner_testkit::FakeFs;
use common::{blocks, harness, home, rule_report};

fn safe(id: &str, roots: &[&str]) -> Rule {
    Rule::new(id, Tier::Safe, roots)
}

/// # Design promise
/// AC-002-17 / INV-11: one run writes `run_start`, one `scan_result` per rule (in rule order, with
/// the per-rule counters) and `run_end` (exit code, totals, `interrupted`), all with the same
/// `run_id` and a gap-free `seq`; `skipped` records fall between `run_start` and `run_end`.
///
/// # Scenario (Given)
/// Rule `a` (a file, a hardlink of it, and one entry that vanishes), rule `b` (one file and one
/// entry denied with EPERM), rule `c` (absent root).
///
/// # Action (When)
/// `run_scan` with a healthy in-memory audit log, then decode every written line.
///
/// # Expected (Then)
/// `seq == 1..=n`, every `run_id == "RUN-0001"` (= `report.run_id`); first record `run_start` with
/// argv `["cleaner","scan"]`, rule ids `[a,b,c]`, version `0.0.0-test`, home `/Users/u`; exactly
/// three `scan_result` in order a, b, c whose status/bytes/items/logical/skipped/vanished/deduped
/// equal the report's; exactly one `skipped` record (the denied path, `permission_denied`) located
/// between start and end; last record `run_end` with `exit_code == report.exit_code() == 4`,
/// `interrupted == false`, `total_bytes`/`total_items` equal to the sums over the rules.
///
/// # Must never
/// Skip a seq; mix run ids; write a record after `run_end`; let the log disagree with the report.
///
/// # Would catch
/// A run without `run_end`, a seq restarting per rule, counters missing in `scan_result`, totals
/// that include purgeable space, `skipped` written after `run_end`.
///
/// # Why this test (not redundant)
/// The only structural test of the run's audit trail; the cap and the failure modes are separate.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture, many structural assertions on the audit trail"
)]
fn ac_002_17_a_run_writes_start_one_result_per_rule_and_end_with_gapless_seq() {
    // Arrange
    let fs = FakeFs::builder()
        .file_sized(home("a/f"), 4096, blocks(4096))
        .ino(home("a/f"), 42, 1)
        .hardlink(home("a/g"), home("a/f"))
        .file_sized(home("a/gone"), 4096, blocks(4096))
        .error_at(home("a/gone"), 2)
        .file_sized(home("b/ok"), 8192, blocks(8192))
        .file_sized(home("b/locked"), 4096, blocks(4096))
        .error_at(home("b/locked"), 1)
        .dir("/Users/u")
        .build();
    let h = harness(fs);

    // Act
    let report = h.scan(
        &[safe("a", &["a"]), safe("b", &["b"]), safe("c", &["c"])],
        5,
    );
    let records = h.records();

    // Assert
    let seqs: Vec<u64> = records.iter().map(|d| d.seq).collect();
    let n = records.len() as u64;
    assert_eq!(
        seqs,
        (1..=n).collect::<Vec<_>>(),
        "INV-11: seq must be gap-free from 1"
    );
    assert!(
        n > 2
            && records
                .iter()
                .all(|d| d.run_id == "RUN-0001" && d.run_id == report.run_id),
        "every record carries the run's id (and the run wrote more than start/end), got {n} records"
    );
    assert_eq!(
        records.first().map(|d| &d.record),
        Some(&Record::RunStart {
            argv: vec!["cleaner".to_owned(), "scan".to_owned()],
            rule_ids: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
            version: "0.0.0-test".to_owned(),
            home: "/Users/u".into(),
        }),
        "the first record must be run_start with argv, rule ids in order, version and home"
    );
    let results: Vec<&Record> = records
        .iter()
        .map(|d| &d.record)
        .filter(|r| matches!(r, Record::ScanResult { .. }))
        .collect();
    assert_eq!(results.len(), 3, "exactly one scan_result per rule");
    for (rec, id) in results.iter().zip(["a", "b", "c"]) {
        let r = rule_report(&report, id);
        let Record::ScanResult {
            rule_id,
            status,
            bytes,
            items,
            counts,
        } = rec
        else {
            unreachable!("filtered above")
        };
        assert_eq!(rule_id, id, "scan_result order must follow rule order");
        assert_eq!(status, r.status.as_str(), "{id}: status");
        assert_eq!(
            (*bytes, *items),
            (r.bytes, r.items),
            "{id}: bytes and items"
        );
        assert_eq!(
            (
                counts.logical_bytes,
                counts.skipped,
                counts.skipped_unlogged,
                counts.vanished,
                counts.deduped_links
            ),
            (r.logical_bytes, r.skipped, 0, r.vanished, r.deduped_links),
            "{id}: counters in the record must equal the report"
        );
    }
    assert_eq!(
        (
            rule_report(&report, "a").vanished,
            rule_report(&report, "a").deduped_links
        ),
        (1, 1),
        "fixture sanity: rule a saw one vanished entry and one dedupe"
    );
    let skipped_at: Vec<(usize, &Record)> = records
        .iter()
        .enumerate()
        .filter(|(_, d)| matches!(d.record, Record::Skipped { .. }))
        .map(|(i, d)| (i, &d.record))
        .collect();
    assert_eq!(skipped_at.len(), 1, "one skipped record (the EPERM entry)");
    assert!(
        matches!(skipped_at[0].1, Record::Skipped { path, reason } if *path == home("b/locked") && reason == "permission_denied"),
        "the skipped record names the path and reason"
    );
    assert!(
        skipped_at[0].0 > 0 && skipped_at[0].0 < records.len() - 1,
        "skipped records belong between run_start and run_end"
    );
    assert_eq!(
        records.last().map(|d| &d.record),
        Some(&Record::RunEnd {
            exit_code: 4,
            interrupted: false,
            total_bytes: report.rules.iter().map(|r| r.bytes).sum(),
            total_items: report.rules.iter().map(|r| r.items).sum(),
        }),
        "the last record must be run_end with the report's exit code (4: a skip) and totals"
    );
    assert_eq!(
        report.exit_code(),
        4,
        "report and run_end agree on the exit code"
    );
}

/// # Design promise
/// AC-002-17: at most 1000 `skipped` records are written **per run**; entries beyond the cap are
/// still skipped and counted, and each rule's `scan_result` carries how many of its skips were not
/// logged (`skipped_unlogged`).
///
/// # Scenario (Given)
/// Rows `(files denied in rule a, files denied in rule b)`: `(1000, 0)` (exactly at the cap),
/// `(1001, 0)` (one over), `(600, 600)` (the cap is per run, not per rule). Every denied entry is a
/// file failing `lstat` with EPERM.
///
/// # Action (When)
/// `run_scan` with a healthy audit log.
///
/// # Expected (Then)
/// Number of `skipped` records == `min(a + b, 1000)`; `report.skipped` is `a` and `b` in full; the
/// `scan_result` counters: `(1000,0)`: unlogged 0; `(1001,0)`: unlogged 1; `(600,600)`: `a` unlogged
/// 0 and `b` unlogged 200.
///
/// # Must never
/// Write a 1001st skipped record; lose the count of unlogged skips; cap per rule instead of per run.
///
/// # Would catch
/// No cap (an unreadable `~/Library/Caches` with 500k entries would write a 100 MB log), an
/// off-by-one at 1000/1001, overflow not reported, per-rule counters.
///
/// # Why this test (not redundant)
/// The only coverage of the cap and its bookkeeping.
#[test]
fn ac_002_17_skipped_records_are_capped_at_1000_per_run_and_the_overflow_is_counted() {
    // Arrange
    let rows = [
        (1000_usize, 0_usize, 0_u64, 0_u64),
        (1001, 0, 1, 0),
        (600, 600, 0, 200),
    ];

    for (a_count, b_count, want_a_unlogged, want_b_unlogged) in rows {
        let mut b = FakeFs::builder().dir(home("a")).dir(home("b"));
        for (root, count) in [("a", a_count), ("b", b_count)] {
            for i in 0..count {
                let p = home(root).join(format!("f{i:04}"));
                b = b.file_sized(&p, 4096, blocks(4096)).error_at(&p, 1);
            }
        }
        let h = harness(b.build());

        // Act
        let report = h.scan(&[safe("a", &["a"]), safe("b", &["b"])], 0);

        // Assert
        let logged = h
            .records()
            .iter()
            .filter(|d| matches!(d.record, Record::Skipped { .. }))
            .count();
        let label = format!("rows ({a_count}, {b_count})");
        assert_eq!(
            logged,
            (a_count + b_count).min(1000),
            "{label}: skipped records are capped at 1000 per run"
        );
        assert_eq!(
            (
                rule_report(&report, "a").skipped,
                rule_report(&report, "b").skipped
            ),
            (a_count as u64, b_count as u64),
            "{label}: the report counts every skip, logged or not"
        );
        let unlogged: Vec<u64> = h
            .records()
            .iter()
            .filter_map(|d| match &d.record {
                Record::ScanResult { counts, .. } => Some(counts.skipped_unlogged),
                _ => None,
            })
            .collect();
        assert_eq!(
            unlogged,
            vec![want_a_unlogged, want_b_unlogged],
            "{label}: scan_result.skipped_unlogged per rule"
        );
    }
}

/// # Design promise
/// AC-002-17 / INV-13 (read-only scan may continue): if the audit sink is unavailable (could not be
/// opened) or fails while writing, the scan still completes with correct numbers, the report says
/// `audit_unavailable`, and the exit code is 4. A healthy sink leaves the flag off and exits 0.
///
/// # Scenario (Given)
/// One rule with a 4 KiB file. Rows: no audit log at all (`None`: `FileAuditSink::open` failed), a
/// sink whose every write fails, a healthy sink.
///
/// # Action (When)
/// `run_scan`.
///
/// # Expected (Then)
/// Rows 1-2: `audit_unavailable == true`, rule bytes 4096, `exit_code() == 4`. Row 3:
/// `audit_unavailable == false`, `exit_code() == 0`.
///
/// # Must never
/// Panic, abort or skip the scan because the log is unusable; report success silently.
///
/// # Would catch
/// `?` on the audit result (aborting the scan), swallowing the failure without a flag, using exit 0.
///
/// # Why this test (not redundant)
/// The only coverage of the sink-failure policy at the core level; the stderr warning is CLI.
#[test]
fn ac_002_17_scan_completes_and_flags_audit_unavailable_when_the_sink_fails() {
    // Arrange
    let rows = [
        ("no audit log (sink unavailable)", false, 0_u32, true),
        ("sink fails every write", true, u32::MAX, true),
        ("healthy sink", true, 0, false),
    ];

    for (name, with_log, failing_writes, want_flag) in rows {
        let fs = FakeFs::builder()
            .file_sized(home("Library/Caches/a"), 4096, blocks(4096))
            .build();
        let h = harness(fs);
        h.sink.fail_next_writes(failing_writes);
        let rules = [safe("user-caches", &["Library/Caches"])];

        // Act
        let report = h.run(&h.fs, &rules, 5, &CancelToken::new(), with_log);

        // Assert
        assert_eq!(
            report.audit_unavailable, want_flag,
            "{name}: audit_unavailable flag"
        );
        assert_eq!(
            rule_report(&report, "user-caches").bytes,
            4096,
            "{name}: the scan must still complete"
        );
        assert_eq!(
            report.exit_code(),
            if want_flag { 4 } else { 0 },
            "{name}: unavailable log -> exit 4, healthy -> 0"
        );
    }
}

mod safety {
    use super::*;

    /// # Design promise
    /// AC-002-15 / INV-01 / INV-10: a scan changes nothing: the filesystem (content, kinds, sizes,
    /// mtimes, inodes) is identical afterwards, the only command run is the read-only `tmutil
    /// listlocalsnapshots /`, and a second scan of the same tree gives the same result.
    ///
    /// # Scenario (Given)
    /// A tree with files, a symlink, a hardlink, a directory on another device and an unreadable
    /// entry (so every branch of the walker runs); `FakeFs::snapshot()` taken before.
    ///
    /// # Action (When)
    /// `run_scan` twice.
    ///
    /// # Expected (Then)
    /// `snapshot()` after equals before; each scan made exactly one runner call (`listlocalsnapshots /`),
    /// none with `sudo`; both scans report equal rules.
    ///
    /// # Must never
    /// Mutate any node; run any other command.
    ///
    /// # Would catch
    /// A walker that "fixes" a path, touches mtimes, or calls a second process; state kept between
    /// runs that changes the second result.
    ///
    /// # Why this test (not redundant)
    /// The behavioral half of INV-01 for the scan (the type-level half is that `ScanPorts` offers
    /// only read-only ports); it exercises all walker branches in one go.
    #[test]
    fn ac_002_15_a_scan_leaves_the_tree_untouched_and_runs_only_the_read_only_command() {
        // Arrange
        let c = home("Library/Caches");
        let fs = FakeFs::builder()
            .file_sized(c.join("a"), 4096, blocks(4096))
            .mtime_secs(c.join("a"), 1234)
            .symlink(c.join("link"), "/Users/u/elsewhere")
            .size(c.join("link"), 10, 8)
            .hardlink(c.join("a2"), c.join("a"))
            .file_sized(c.join("mnt/x"), 4096, blocks(4096))
            .dev(c.join("mnt"), 9)
            .file_sized(c.join("locked"), 4096, blocks(4096))
            .error_at(c.join("locked"), 13)
            .build();
        let h = harness(fs);
        let rules = [safe("user-caches", &["Library/Caches"])];
        let before = h.fs.snapshot();

        // Act
        let first = h.scan(&rules, 5);
        let second = h.scan(&rules, 5);

        // Assert
        assert_eq!(
            h.fs.snapshot(),
            before,
            "INV-01: the scanned tree must be byte-for-byte unchanged"
        );
        let calls = h.runner.calls();
        assert_eq!(
            calls.len(),
            2,
            "one tmutil call per scan and nothing else, got {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|c| c.args == ["listlocalsnapshots", "/"] && !c.program.contains("sudo")),
            "INV-10: only the read-only listing, never sudo: {calls:?}"
        );
        assert_eq!(first.rules, second.rules, "a scan must be repeatable");
        assert_eq!(
            rule_report(&first, "user-caches").items,
            2,
            "fixture sanity: `a` and the symlink count; `a2` is a dedupe; the mount and the locked file are skipped"
        );
    }
}

/// A read-only wrapper around the harness filesystem that sets the cancel token once its
/// `read_dir` has been called `cancel_after` times (the call itself still completes): the
/// deterministic stand-in for "SIGINT arrived while a directory was being read".
struct CancellingFs<'a> {
    inner: &'a FakeFs,
    token: &'a CancelToken,
    cancel_after: usize,
    listed: AtomicUsize,
}

impl Fs for CancellingFs<'_> {
    fn lstat(&self, path: &Path) -> io::Result<Metadata> {
        self.inner.lstat(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let entries = self.inner.read_dir(path);
        if self.listed.fetch_add(1, Ordering::SeqCst) + 1 >= self.cancel_after {
            self.token.cancel();
        }
        entries
    }
}

/// # Design promise
/// AC-002-18: once the cancel token is set, no further directory is listed; the results so far are
/// reported with `incomplete: true` and `interrupted: true`, rules that did not finish are
/// `interrupted` (never a misleading `ok`), exit code 130, and `run_end` is still written with
/// `interrupted: true`.
///
/// # Scenario (Given)
/// Rules `first` (one file), `second` (ten subdirectories with a file each) and `third` (one file).
/// Row 1: the token is cancelled before the scan starts. Row 2: the token is cancelled while the 3rd
/// directory listing runs (root of `first`, root of `second`, `second/s0`).
///
/// # Action (When)
/// `run_scan` through a `CancellingFs` (row 2) or the plain fake (row 1).
///
/// # Expected (Then)
/// Row 1: no `read_dir` at all; all three rules `interrupted`, 0 bytes. Row 2: at most 3 `read_dir`
/// calls (the batch in flight finishes, nothing after); `first` is `ok` with 4096 bytes; `second`
/// and `third` are `interrupted`; `third` has 0 bytes. Both rows: `incomplete`, `interrupted`,
/// `exit_code() == 130`; the last audit record is `run_end` with `interrupted == true`,
/// `exit_code == 130` and `total_bytes` equal to the report's sum.
///
/// # Must never
/// Keep walking after cancellation; report an unfinished rule as `ok`; skip `run_end`.
///
/// # Would catch
/// A walker that never polls the token (or only at rule boundaries), polling only between rules,
/// forgetting `run_end` on the interrupted path, exit 4 instead of 130.
///
/// # Why this test (not redundant)
/// The only core-level cancellation test (SIGINT delivery is one CLI test in slice 002b).
#[test]
fn ac_002_18_cancelling_stops_listing_and_reports_an_incomplete_interrupted_run() {
    // Arrange
    let build = || {
        let mut b = FakeFs::builder()
            .file_sized(home("first/f"), 4096, blocks(4096))
            .file_sized(home("third/f"), 4096, blocks(4096));
        for i in 0..10 {
            b = b.file_sized(home("second").join(format!("s{i}/f")), 4096, blocks(4096));
        }
        b.build()
    };
    let rules = [
        safe("first", &["first"]),
        safe("second", &["second"]),
        safe("third", &["third"]),
    ];
    let statuses = |r: &cleaner_core::report::ScanReport| -> Vec<&'static str> {
        r.rules.iter().map(|x| x.status.as_str()).collect()
    };

    // Row 1: cancelled before the scan.
    let h = harness(build());
    let token = CancelToken::new();
    token.cancel();

    // Act
    let report = h.run(&h.fs, &rules, 5, &token, true);

    // Assert
    assert!(
        h.fs.read_dir_calls().is_empty(),
        "pre-cancelled: no directory may be listed"
    );
    assert_eq!(
        statuses(&report),
        vec!["interrupted"; 3],
        "pre-cancelled: nothing was scanned, nothing may claim `ok`"
    );
    assert_eq!(
        report.rules.iter().map(|r| r.bytes).sum::<u64>(),
        0,
        "pre-cancelled: no bytes may be reported"
    );
    check_interrupted_run(&h, &report, "pre-cancelled");

    // Row 2: cancelled while the 3rd listing runs.
    let h = harness(build());
    let token = CancelToken::new();
    let fs = CancellingFs {
        inner: &h.fs,
        token: &token,
        cancel_after: 3,
        listed: AtomicUsize::new(0),
    };

    // Act
    let report = h.run(&fs, &rules, 5, &token, true);

    // Assert
    assert!(
        h.fs.read_dir_calls().len() <= 3,
        "mid-walk: no listing after the cancelled batch, got {:?}",
        h.fs.read_dir_calls()
    );
    assert_eq!(
        statuses(&report),
        vec!["ok", "interrupted", "interrupted"],
        "mid-walk: the finished rule keeps `ok`; the in-flight and unstarted rules are interrupted"
    );
    assert_eq!(
        (report.rules[0].bytes, report.rules[2].bytes),
        (4096, 0),
        "mid-walk: the finished rule keeps its bytes; the unstarted rule has none"
    );
    check_interrupted_run(&h, &report, "mid-walk");
}

/// Asserts the report/audit flags every interrupted run must show (shared by both rows above).
fn check_interrupted_run(
    h: &common::Harness,
    report: &cleaner_core::report::ScanReport,
    label: &str,
) {
    assert!(
        report.incomplete && report.interrupted,
        "{label}: incomplete and interrupted must be set"
    );
    assert_eq!(report.exit_code(), 130, "{label}: interrupted exits 130");
    let last = h.records().pop().map(|d| d.record);
    assert_eq!(
        last,
        Some(Record::RunEnd {
            exit_code: 130,
            interrupted: true,
            total_bytes: report.rules.iter().map(|r| r.bytes).sum(),
            total_items: report.rules.iter().map(|r| r.items).sum(),
        }),
        "{label}: run_end must still be written, flagged interrupted"
    );
}
