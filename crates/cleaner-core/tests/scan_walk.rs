//! The shared walker: size accounting, symlinks, devices, unreadable and vanishing entries, absent
//! and refused roots, age filter, excludes, nesting and top children (spec 002 AC-002-4 .. AC-002-13,
//! AC-002-22; INV-07, INV-08, INV-09, INV-12). Everything runs against the in-memory `FakeFs`.
//!
//! # Worksheet - `scan::run_scan` (walk part)
//! ```text
//! Function:        scan::run_scan(ports, opts, cancel, audit) -> ScanReport   (walk + accounting)
//! Contract:        per rule: bytes = sum(blocks*512) of regular files and symlinks (a symlink counts
//!                  as itself, never entered), logical = sum(len), items = count; directories and
//!                  other node kinds are not counted; hardlinks once per (dev, ino) across the run,
//!                  first rule in rule order wins, later sightings tallied in deduped_links;
//!                  saturating sums; a directory on another device than its root is not listed
//!                  (cross_device skip); EPERM/EACCES -> skipped permission_denied + status partial,
//!                  one attempt only; ENOENT on a listed entry -> vanished, not partial; no root
//!                  present -> absent; roots refused by the guard (symlink, denied, `..`, absolute)
//!                  -> refused and never listed; min_age counts only regular files with
//!                  mtime <= now - min_age; excludes are not counted nor claimed; nested roots are
//!                  claimed by the most specific rule (no double counting); `top` = up to N largest
//!                  immediate children of the roots (bytes desc, path bytes asc); the walk is
//!                  iterative and independent of read_dir order. (AC-002-4..13, AC-002-22)
//! Equivalence classes: see each test's Scenario; one test per AC class
//! Boundaries:      min_age threshold +-1 s; u64 saturation; 1000/1001 skip cap (audit file);
//!                  top N = 0 / < children / > children; depth 10 000
//! Must-never:      follow or list a symlink; list another device; retry a denied entry; count an
//!                  inode twice; list a refused root; overflow the stack
//! Selected tests:  see fns below
//! Deliberately not tested: `Other` kinds beyond "not counted", entries whose name is not UTF-8
//!                  in the walk (covered by the report test for `path_b64`), real I/O (slice 002b).
//! ```

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use cleaner_core::audit::Record;
use cleaner_core::rules::{Rule, Tier};
use cleaner_testkit::{FakeFs, deep_path};
use common::{DAY, NOW, blocks, harness, home, rule_report};

const KIB: u64 = 1024;

/// A Safe rule named `id` over `roots` (relative to HOME).
fn safe(id: &str, roots: &[&str]) -> Rule {
    Rule::new(id, Tier::Safe, roots)
}

/// # Design promise
/// AC-002-4 / INV-12: bytes are *allocated* (`blocks * 512`), logical bytes are `len`; a zero-byte
/// file is 0 bytes and one item; a sparse file's allocation is below its logical size; directories
/// (with their own nonzero allocation) and non-regular nodes are not counted.
///
/// # Scenario (Given)
/// Rule root `Library/Caches` holding: a zero-byte file; `sub/regular` (len 5000, 16 blocks = 8192
/// allocated); `sub/sparse` (len 1 MiB, 8 blocks = 4096 allocated); a socket node and the two
/// directories, all three with a nonzero block count that must be ignored.
///
/// # Action (When)
/// `run_scan` with that one rule.
///
/// # Expected (Then)
/// `bytes == 12288` (8192 + 4096), `logical_bytes == 1_053_576`, `items == 3`, status `ok`. The
/// sparse file contributes 4096 allocated although it is 1 MiB long.
///
/// # Must never
/// Use `len` for the byte total; count directory or socket allocations; count a zero-byte file as 0
/// items.
///
/// # Would catch
/// Summing `st_size` (a sparse VM image would be reported 256x too large), counting directories'
/// own blocks, forgetting that empty files are still items.
///
/// # Why this test (not redundant)
/// The only test of the basic per-entry counting rules; links, saturation and age have their own.
#[test]
fn ac_002_4_allocated_bytes_logical_bytes_zero_byte_files_and_uncounted_nodes() {
    // Arrange
    let root = home("Library/Caches");
    let fs = FakeFs::builder()
        .dir(&root)
        .size(&root, 64, 8)
        .file(root.join("zero"))
        .file_sized(root.join("sub/regular"), 5000, blocks(8192))
        .file_sized(root.join("sub/sparse"), KIB * KIB, blocks(4096))
        .size(root.join("sub"), 64, 8)
        .other(root.join("sock"))
        .size(root.join("sock"), 0, 8)
        .build();
    let h = harness(fs);

    // Act
    let report = h.scan(&[safe("user-caches", &["Library/Caches"])], 5);

    // Assert
    let r = rule_report(&report, "user-caches");
    assert_eq!(
        r.bytes, 12_288,
        "INV-12: allocated bytes of regular files only (8192 + 4096)"
    );
    assert_eq!(
        r.logical_bytes,
        5000 + KIB * KIB,
        "logical bytes are the sum of st_size"
    );
    assert_eq!(
        r.items, 3,
        "zero-byte file counts as an item; dirs and sockets do not"
    );
    assert_eq!(r.status.as_str(), "ok", "a clean walk is `ok`");
}

/// # Design promise
/// AC-002-4 (saturating arithmetic): sums never overflow or panic; at the limit they stick to
/// `u64::MAX`, per rule and in the tier totals.
///
/// # Scenario (Given)
/// Rule `a`: a file with `blocks == u64::MAX` (its `blocks * 512` overflows by itself) and `len ==
/// u64::MAX`, plus a normal 4 KiB file. Rule `b`: two files of `u64::MAX / 512` blocks each (each
/// fits, their sum does not). Both rules are `Safe`.
///
/// # Action (When)
/// `run_scan` in a debug (overflow-checking) test build.
///
/// # Expected (Then)
/// `a.bytes == u64::MAX`, `a.logical_bytes == u64::MAX`, `b.bytes == u64::MAX`, `totals.safe ==
/// u64::MAX`; no panic.
///
/// # Must never
/// Panic on overflow; wrap around to a small number (which would under-report a huge directory).
///
/// # Would catch
/// Plain `+`/`*` instead of `saturating_*`/`checked_*` on bytes, logical bytes or tier totals.
///
/// # Why this test (not redundant)
/// The only overflow test; it needs absurd inputs no other fixture has.
#[test]
fn ac_002_4_sums_saturate_instead_of_overflowing() {
    // Arrange
    let fs = FakeFs::builder()
        .file_sized(home("a/huge"), u64::MAX, u64::MAX)
        .file_sized(home("a/normal"), 4096, blocks(4096))
        .file_sized(home("b/one"), 1, u64::MAX / 512)
        .file_sized(home("b/two"), 1, u64::MAX / 512)
        .build();
    let h = harness(fs);

    // Act
    let report = h.scan(&[safe("a", &["a"]), safe("b", &["b"])], 5);

    // Assert
    let (a, b) = (rule_report(&report, "a"), rule_report(&report, "b"));
    assert_eq!(
        a.bytes,
        u64::MAX,
        "blocks*512 must saturate, and the sum must stay saturated"
    );
    assert_eq!(a.logical_bytes, u64::MAX, "logical sum must saturate");
    assert_eq!(
        b.bytes,
        u64::MAX,
        "the sum of two near-max files must saturate, not wrap"
    );
    assert_eq!(
        report.totals.safe,
        u64::MAX,
        "tier totals must saturate too"
    );
}

/// # Design promise
/// AC-002-8: an entry that was listed but is gone when examined (`ENOENT`) is counted in `vanished`;
/// it is not an error, does not make the rule `partial`, writes no `skipped` record and keeps the
/// exit code at 0 (a cache file deleted by its owner mid-scan is normal).
///
/// # Scenario (Given)
/// Two rows: a listed *file* whose `lstat` fails with ENOENT; a listed *directory* whose `read_dir`
/// fails with ENOENT. Each next to a normal 4 KiB sibling.
///
/// # Action (When)
/// `run_scan`.
///
/// # Expected (Then)
/// `vanished == 1`, status `ok`, `skipped == 0`, `bytes == 4096` (the sibling), no `skipped` audit
/// record, `exit_code() == 0`.
///
/// # Must never
/// Treat the vanished entry as permission trouble, as an absent root, or as a reason to abort.
///
/// # Would catch
/// Mapping every `lstat` error to `skipped`, using `NotFound` to mean "root absent" for children,
/// setting `partial`.
///
/// # Why this test (not redundant)
/// The only coverage of AC-002-8 (the ENOENT branch of error classification).
#[test]
fn ac_002_8_vanished_entries_are_counted_not_errors() {
    // Arrange
    let root = home("Library/Caches");
    let rows: [(&str, FakeFs); 2] = [
        (
            "file vanished before lstat",
            FakeFs::builder()
                .file_sized(root.join("keep"), 4096, blocks(4096))
                .file_sized(root.join("gone"), 4096, blocks(4096))
                .error_at(root.join("gone"), 2)
                .build(),
        ),
        (
            "directory vanished before listing",
            FakeFs::builder()
                .file_sized(root.join("keep"), 4096, blocks(4096))
                .file_sized(root.join("gonedir/inside"), 4096, blocks(4096))
                .list_error_at(root.join("gonedir"), 2)
                .build(),
        ),
    ];

    for (name, fs) in rows {
        let h = harness(fs);

        // Act
        let report = h.scan(&[safe("user-caches", &["Library/Caches"])], 5);

        // Assert
        let r = rule_report(&report, "user-caches");
        assert_eq!(r.vanished, 1, "{name}: the vanished entry must be counted");
        assert_eq!(r.status.as_str(), "ok", "{name}: vanishing is not partial");
        assert_eq!(r.skipped, 0, "{name}: vanishing is not a skip");
        assert_eq!(r.bytes, 4096, "{name}: the sibling is still counted");
        assert!(
            !h.records()
                .iter()
                .any(|d| matches!(d.record, Record::Skipped { .. })),
            "{name}: no skipped record for a vanished entry"
        );
        assert_eq!(report.exit_code(), 0, "{name}: exit code stays 0");
    }
}

/// # Design promise
/// AC-002-10: a root that does not exist is `absent` with 0 bytes - not an error, no skip, exit 0.
/// A rule with several roots is `absent` only when *none* exists.
///
/// # Scenario (Given)
/// Rule `gone` whose only root is missing; rule `some` with roots `a` (missing) and `b` (4 KiB file).
///
/// # Action (When)
/// `run_scan` with both rules.
///
/// # Expected (Then)
/// `gone`: status `absent`, 0 bytes, 0 items, 0 skipped. `some`: status `ok`, 4096 bytes. The audit
/// log has `scan_result` status `absent` for `gone`. Overall `exit_code() == 0`.
///
/// # Must never
/// Report `absent` for a rule that has data; report an absent root as an error or skip; exit 4.
///
/// # Would catch
/// Treating `ENOENT` on a root as `partial`/`permission_denied`, or marking a multi-root rule absent
/// because its first root is missing.
///
/// # Why this test (not redundant)
/// The only coverage of AC-002-10.
#[test]
fn ac_002_10_absent_roots_are_reported_absent_not_as_errors() {
    // Arrange
    let fs = FakeFs::builder()
        .dir("/Users/u")
        .file_sized(home("b/f"), 4096, blocks(4096))
        .build();
    let h = harness(fs);

    // Act
    let report = h.scan(&[safe("gone", &["nowhere"]), safe("some", &["a", "b"])], 5);

    // Assert
    let gone = rule_report(&report, "gone");
    assert_eq!(gone.status.as_str(), "absent", "no root exists -> absent");
    assert_eq!(
        (gone.bytes, gone.items, gone.skipped),
        (0, 0, 0),
        "absent contributes nothing"
    );
    let some = rule_report(&report, "some");
    assert_eq!(
        some.status.as_str(),
        "ok",
        "one of two roots exists -> not absent"
    );
    assert_eq!(some.bytes, 4096, "the existing root is counted");
    let logged_absent = h.records().iter().any(|d| {
        matches!(&d.record, Record::ScanResult { rule_id, status, .. } if rule_id == "gone" && status == "absent")
    });
    assert!(
        logged_absent,
        "the audit log must record the absent rule as status `absent`"
    );
    assert_eq!(report.exit_code(), 0, "AC-002-10: absent roots exit 0");
}

/// # Design promise
/// AC-002-12: for a rule with `min_age`, only **regular files** with `mtime <= now - min_age` count;
/// exactly at the threshold counts; a future mtime does not; directories are not counted themselves
/// but their eligible files are (the age of a directory is irrelevant); rules without `min_age` are
/// unaffected.
///
/// # Scenario (Given)
/// `now` = 2027-01-15 08:00 UTC (injected clock); rule `old-downloads` (Caution, 90 days) over
/// `Downloads`, files with distinct block counts (so the byte total identifies which counted):
/// at the threshold (1 block, counted), 1 s newer (2, not), 1 s older (4, counted), `now + 1 s` (8,
/// not), ten years in the future (16, not), mtime at the epoch (32, counted), an old *symlink* (64,
/// not: the rule counts regular files only), an old directory holding an old file (256, counted), a
/// brand-new directory holding an old file (1024, counted). A second rule without `min_age` over
/// `Recent` holds a future-dated 4 KiB file.
///
/// # Action (When)
/// `run_scan` with both rules.
///
/// # Expected (Then)
/// `old-downloads`: items 5 and bytes `(1 + 4 + 32 + 256 + 1024) * 512 = 674_304`; the unfiltered rule
/// counts its future-dated file (4096 bytes).
///
/// # Must never
/// Count a file newer than the threshold or dated in the future; use atime (not even available).
///
/// # Would catch
/// `<` instead of `<=` (threshold file lost), `>=` inverted comparisons, applying the age to
/// directories (dropping their old files), counting symlinks under an age rule, applying the filter
/// to rules that do not ask for it.
///
/// # Why this test (not redundant)
/// The only test of the age filter, all boundaries in one fixture.
#[test]
fn ac_002_12_age_filter_counts_only_old_enough_regular_files() {
    // Arrange
    let d = home("Downloads");
    let ninety = 90 * DAY;
    let fs = FakeFs::builder()
        .file_sized(d.join("at_threshold"), 1, 1)
        .mtime_secs(d.join("at_threshold"), NOW - ninety)
        .file_sized(d.join("one_second_newer"), 1, 2)
        .mtime_secs(d.join("one_second_newer"), NOW - ninety + 1)
        .file_sized(d.join("one_second_older"), 1, 4)
        .mtime_secs(d.join("one_second_older"), NOW - ninety - 1)
        .file_sized(d.join("future"), 1, 8)
        .mtime_secs(d.join("future"), NOW + 1)
        .file_sized(d.join("far_future"), 1, 16)
        .mtime_secs(d.join("far_future"), NOW + 3650 * DAY)
        .file_sized(d.join("epoch"), 1, 32)
        .mtime_secs(d.join("epoch"), 0)
        .symlink(d.join("old_link"), "/nowhere")
        .size(d.join("old_link"), 1, 64)
        .mtime_secs(d.join("old_link"), 0)
        .dir(d.join("old_dir"))
        .size(d.join("old_dir"), 1, 128)
        .mtime_secs(d.join("old_dir"), 0)
        .file_sized(d.join("old_dir/inside"), 1, 256)
        .mtime_secs(d.join("old_dir/inside"), 0)
        .dir(d.join("fresh_dir"))
        .size(d.join("fresh_dir"), 1, 512)
        .mtime_secs(d.join("fresh_dir"), NOW)
        .file_sized(d.join("fresh_dir/old_inside"), 1, 1024)
        .mtime_secs(d.join("fresh_dir/old_inside"), 0)
        .file_sized(home("Recent/new"), 1, 8)
        .mtime_secs(home("Recent/new"), NOW + 1000)
        .build();
    let h = harness(fs);
    let mut downloads = Rule::new("old-downloads", Tier::Caution, &["Downloads"]);
    downloads.min_age = Some(Duration::from_hours(90 * 24));

    // Act
    let report = h.scan(&[downloads, safe("plain", &["Recent"])], 5);

    // Assert
    let r = rule_report(&report, "old-downloads");
    assert_eq!(
        r.items, 5,
        "AC-002-12: threshold, older, epoch, and the two files inside directories"
    );
    assert_eq!(
        r.bytes,
        (1 + 4 + 32 + 256 + 1024) * 512,
        "AC-002-12: bytes identify which files counted (threshold counts, future/newer/symlink/dirs do not)"
    );
    assert_eq!(
        rule_report(&report, "plain").bytes,
        4096,
        "a rule without min_age must not apply any age filter"
    );
}

/// # Design promise
/// AC-002-13: `top` holds up to N immediate children of the rule's roots (all roots pooled), by
/// allocated bytes descending, ties broken by **path bytes** ascending (deterministic, locale
/// independent); N = 0 yields an empty list; N larger than the number of children yields them all.
///
/// # Scenario (Given)
/// One rule with roots `a` and `b`. Children: `a/dir` (two 4 KiB files = 8192), `a/B` and `a/a` and
/// `b/f2` (4096 each: a three-way tie where byte order puts upper-case `B` before `a`), `b/zz` (a
/// directory with one 1024-byte file), `a/small` (512), plus two
/// zero-byte children: the empty directory `a/empty-dir` and the zero-byte file `b/zero-file`.
///
/// # Action (When)
/// `run_scan` with N = 4, N = 0 and N = 10.
///
/// # Expected (Then)
/// N=4: `[a/dir 8192, a/B 4096, a/a 4096, b/f2 4096]`. N=0: `[]`. N=10: those four, then `b/zz 1024`,
/// `a/small 512`. Paths are absolute under `/Users/u`. The empty directory `a/empty-dir` and the
/// zero-byte file `b/zero-file` never appear, even with N = 10 (room for them): a child with 0
/// allocated bytes is not a "top" entry (ratified D15).
///
/// # Must never
/// Order ties by anything but path bytes; return more than N; include grandchildren as entries; list
/// a child that holds 0 allocated bytes.
///
/// # Would catch
/// Sorting ascending, locale/case-insensitive tie-break (`a` before `B`), per-root instead of pooled
/// top lists, a child directory reported with only its first file's size, off-by-one on N,
/// filling spare slots with empty children (a `retain(bytes > 0)` removed from `top_entries`).
///
/// # Why this test (not redundant)
/// The only test of `top` ordering, limits and the zero-byte exclusion; listing-order independence has its own test.
#[test]
fn ac_002_13_top_children_are_ordered_by_bytes_then_path_and_limited_by_n() {
    // Arrange
    let fs = FakeFs::builder()
        .file_sized(home("a/dir/x"), 4096, blocks(4096))
        .file_sized(home("a/dir/y"), 4096, blocks(4096))
        .file_sized(home("a/B"), 4096, blocks(4096))
        .file_sized(home("a/a"), 4096, blocks(4096))
        .file_sized(home("a/small"), 512, blocks(512))
        .file_sized(home("b/f2"), 4096, blocks(4096))
        .file_sized(home("b/zz/z"), 1024, blocks(1024))
        // Children that contribute 0 allocated bytes: an empty directory and a zero-byte file.
        // They are items/children of the root but carry nothing (ratified D15), so never listed.
        .dir(home("a/empty-dir"))
        .file(home("b/zero-file"))
        .build();
    let h = harness(fs);
    let rule = safe("pooled", &["a", "b"]);
    let want_all: Vec<(&str, u64)> = vec![
        ("/Users/u/a/dir", 8192),
        ("/Users/u/a/B", 4096),
        ("/Users/u/a/a", 4096),
        ("/Users/u/b/f2", 4096),
        ("/Users/u/b/zz", 1024),
        ("/Users/u/a/small", 512),
    ];

    for (n, want) in [(4_usize, &want_all[..4]), (0, &[][..]), (10, &want_all[..])] {
        // Act
        let report = h.scan(std::slice::from_ref(&rule), n);

        // Assert
        let got: Vec<(&str, u64)> = rule_report(&report, "pooled")
            .top
            .iter()
            .map(|t| (t.path.as_str(), t.bytes))
            .collect();
        assert_eq!(
            got, want,
            "AC-002-13 with N={n}: (path, bytes) of top children"
        );
    }
}

/// # Design promise
/// AC-002-13 / determinism: the report does not depend on the order in which the OS lists a
/// directory (the real order is unspecified), including which of two hardlinked children gets the
/// bytes.
///
/// # Scenario (Given)
/// One rule; children `c1` and `c2` each holding a hardlink of the same inode (4096), plus two
/// children of equal size (`p`, `q`, 2048). The same tree is served with ascending and with reversed
/// directory listings.
///
/// # Action (When)
/// `run_scan` on each filesystem.
///
/// # Expected (Then)
/// Both reports are identical and total 8192 bytes (4096 once for the inode + 2 x 2048).
///
/// # Must never
/// Let attribution, top order or totals depend on `read_dir` order.
///
/// # Would catch
/// A walker that trusts the listing order (the hardlinked bytes would swap between `c1` and `c2`;
/// ties between `p` and `q` would flip) - a flaky bug on real filesystems.
///
/// # Why this test (not redundant)
/// The only order-independence test; the exact top order is pinned by the test above.
#[test]
fn ac_002_13_results_do_not_depend_on_directory_listing_order() {
    // Arrange: build the same tree twice, once with reversed listings.
    let build = |reverse: bool| {
        let mut b = FakeFs::builder()
            .file_sized(home("r/c1/a"), 4096, blocks(4096))
            .ino(home("r/c1/a"), 900, 1)
            .hardlink(home("r/c2/a"), home("r/c1/a"))
            .file_sized(home("r/p"), 2048, blocks(2048))
            .file_sized(home("r/q"), 2048, blocks(2048));
        if reverse {
            b = b.reverse_read_dir();
        }
        harness(b.build())
    };
    let rules = [safe("r", &["r"])];

    // Act
    let forward = build(false).scan(&rules, 10);
    let reversed = build(true).scan(&rules, 10);

    // Assert
    assert_eq!(
        rule_report(&forward, "r").bytes,
        8192,
        "inode counted once + two 2048 files"
    );
    assert_eq!(
        forward.rules, reversed.rules,
        "per-rule results (bytes, dedup attribution, top order) must not depend on listing order"
    );
}

/// # Design promise
/// Failure mode "very deep trees": the walk is iterative; a directory chain of 10 000 levels neither
/// overflows the stack nor loses the data at the bottom.
///
/// # Scenario (Given)
/// `Library/Caches` + 10 000 nested directories `d/d/.../d` with one 4 KiB file at the bottom and
/// one at the top. The scan runs on a thread with a deliberately small 256 KiB stack (a recursive
/// walker needs far more for 10 000 frames).
///
/// # Action (When)
/// `run_scan`.
///
/// # Expected (Then)
/// `bytes == 8192`, `items == 2`, status `ok` (the process is still alive: no stack overflow).
///
/// # Must never
/// Recurse once per directory level.
///
/// # Would catch
/// A recursive `walk(dir)` implementation (stack overflow / abort at depth ~ stack / frame size).
///
/// # Why this test (not redundant)
/// The only depth test; every other fixture is shallow.
#[test]
fn fm_002_deep_tree_of_10000_levels_is_walked_iteratively() {
    // Arrange
    let root = home("Library/Caches");
    let leaf_dir = deep_path(&root, 10_000);
    let fs = FakeFs::builder()
        .record_calls(false)
        .deep_dirs(&root, 10_000)
        .file_sized(leaf_dir.join("leaf"), 4096, blocks(4096))
        .file_sized(root.join("top"), 4096, blocks(4096))
        .build();
    let h = harness(fs);
    let rules = [safe("user-caches", &["Library/Caches"])];

    // Act: a 256 KiB stack makes a recursive walker overflow long before depth 10 000.
    let report = std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn_scoped(s, || h.scan(&rules, 5))
            .expect("spawn scan thread")
            .join()
            .expect("scan thread must not panic")
    });

    // Assert
    let r = rule_report(&report, "user-caches");
    assert_eq!(
        (r.bytes, r.items),
        (8192, 2),
        "the file at depth 10 000 must be reached and counted"
    );
    assert_eq!(
        r.status.as_str(),
        "ok",
        "a deep but readable tree is a clean scan"
    );
}

mod safety {
    use super::*;

    /// # Design promise
    /// AC-002-4 / INV-12: a hardlinked inode is counted once per `(dev, ino)` across the whole run,
    /// attributed to the first rule *in rule order*; every later sighting (same or different rule) is
    /// tallied in `deduped_links` and adds no bytes or items; the same inode number on another
    /// device is a different file.
    ///
    /// # Scenario (Given)
    /// Inode 777 (4096 bytes) has names `a/f1` and `a/f1b` (rule A) and `b/f1c` (rule B); rule C's
    /// root `c` is a mount point (device 2) holding `c/x`, a different file that reports the same
    /// inode number 777.
    ///
    /// # Action (When)
    /// Scan in order `[A, B, C]`, then in order `[B, A, C]`.
    ///
    /// # Expected (Then)
    /// `[A,B,C]`: A 4096 bytes / 1 item / 1 deduped; B 0 / 0 / 1; C 4096 / 1 / 0.
    /// `[B,A,C]`: B 4096 / 1 / 0; A 0 / 0 / 2; C unchanged. (Ownership follows rule order, not names.)
    ///
    /// # Must never
    /// Count 4096 twice; dedupe by inode number alone (C would lose its bytes).
    ///
    /// # Would catch
    /// No dedup (a Homebrew/Xcode tree full of hardlinks is double counted), per-rule dedup instead
    /// of per-run, a key without `dev`, dedup that depends on path order instead of rule order.
    ///
    /// # Why this test (not redundant)
    /// The only hardlink test; sparse/zero-byte accounting is the first test of this file.
    #[test]
    fn ac_002_4_hardlinks_are_counted_once_per_dev_ino_in_rule_order() {
        // Arrange
        let fs = FakeFs::builder()
            .file_sized(home("a/f1"), 4096, blocks(4096))
            .ino(home("a/f1"), 777, 1)
            .hardlink(home("a/f1b"), home("a/f1"))
            .hardlink(home("b/f1c"), home("a/f1"))
            .dir(home("c"))
            .dev(home("c"), 2)
            .file_sized(home("c/x"), 4096, blocks(4096))
            .ino(home("c/x"), 777, 3)
            .build();
        let h = harness(fs);
        let (rule_a, rule_b, rule_c) = (safe("A", &["a"]), safe("B", &["b"]), safe("C", &["c"]));

        // Act
        let first = h.scan(&[rule_a.clone(), rule_b.clone(), rule_c.clone()], 5);
        let second = h.scan(&[rule_b, rule_a, rule_c], 5);

        // Assert
        let tuple = |r: &cleaner_core::report::ScanReport, id: &str| {
            let rule = rule_report(r, id);
            (rule.bytes, rule.items, rule.deduped_links)
        };
        assert_eq!(
            tuple(&first, "A"),
            (4096, 1, 1),
            "[A,B,C]: A owns the inode, f1b is a dedupe"
        );
        assert_eq!(
            tuple(&first, "B"),
            (0, 0, 1),
            "[A,B,C]: B only sees an already counted inode"
        );
        assert_eq!(
            tuple(&first, "C"),
            (4096, 1, 0),
            "same ino on another device is another file"
        );
        assert_eq!(
            tuple(&second, "B"),
            (4096, 1, 0),
            "[B,A,C]: ownership follows rule order"
        );
        assert_eq!(
            tuple(&second, "A"),
            (0, 0, 2),
            "[B,A,C]: both of A's names are later sightings"
        );
        assert_eq!(tuple(&second, "C"), (4096, 1, 0), "[B,A,C]: C unchanged");
    }

    /// # Design promise
    /// AC-002-5 / INV-07: a symlink contributes only its own `lstat` allocation (as one item); its
    /// target - a large directory, a file, a missing path, or an ancestor (loops) - is never listed
    /// or even examined; symlink loops terminate.
    ///
    /// # Scenario (Given)
    /// `Library/Caches` holds five symlinks, each with its own 4096-byte allocation: to a 3 MiB
    /// directory outside the root, to a file outside, a dangling one, one pointing at its own parent
    /// directory `app`, and `loop/up` pointing at `..`. The outside tree holds three 1 MiB files.
    ///
    /// # Action (When)
    /// `run_scan` with the cache rule.
    ///
    /// # Expected (Then)
    /// `bytes == 5 * 4096`, `items == 5`; no `read_dir` call on any link path or anywhere under
    /// `/Users/u/Outside`; no `lstat` of anything under `/Users/u/Outside`; the real directories
    /// (`Library/Caches`, `app`, `loop`) were listed (the walk did happen).
    ///
    /// # Must never
    /// Enter a symlinked directory, read its target, or loop forever.
    ///
    /// # Would catch
    /// `metadata()` instead of `lstat`, listing a `Symlink` entry because `read_dir` reported `Dir`
    /// for its target, no loop protection (counting 3 MiB x N, or hanging).
    ///
    /// # Why this test (not redundant)
    /// The only scan-level symlink test (the guard's own symlink rules are spec 001); refused root
    /// symlinks are the next test.
    #[test]
    fn ac_002_5_symlinks_count_as_links_and_are_never_entered() {
        // Arrange
        let root = home("Library/Caches");
        let outside = home("Outside");
        let link = |b: cleaner_testkit::FakeFsBuilder, rel: &str, target: &str| {
            let p = root.join(rel);
            b.symlink(&p, target).size(&p, 20, 8)
        };
        let mut b = FakeFs::builder()
            .dir(&root)
            .file_sized(outside.join("big/1"), KIB * KIB, blocks(KIB * KIB))
            .file_sized(outside.join("big/2"), KIB * KIB, blocks(KIB * KIB))
            .file_sized(outside.join("big/3"), KIB * KIB, blocks(KIB * KIB))
            .file_sized(outside.join("f"), KIB * KIB, blocks(KIB * KIB))
            .dir(root.join("app"))
            .dir(root.join("loop"));
        b = link(b, "dirlink", "/Users/u/Outside/big");
        b = link(b, "filelink", "/Users/u/Outside/f");
        b = link(b, "dangling", "/Users/u/nowhere");
        b = link(b, "app/selfloop", "/Users/u/Library/Caches/app");
        b = link(b, "loop/up", "..");
        let fs = b.build();
        let h = harness(fs);

        // Act
        let report = h.scan(&[safe("user-caches", &["Library/Caches"])], 5);

        // Assert
        let r = rule_report(&report, "user-caches");
        assert_eq!(
            r.bytes,
            5 * 4096,
            "INV-07: only the links' own allocation counts"
        );
        assert_eq!(r.items, 5, "each link is one item");
        let listed = h.fs.read_dir_calls();
        let links =
            ["dirlink", "filelink", "dangling", "app/selfloop", "loop/up"].map(|l| root.join(l));
        assert!(
            listed
                .iter()
                .all(|p| !p.starts_with(&outside) && !links.contains(p)),
            "INV-07: a symlink (or anything behind it) was listed: {listed:?}"
        );
        assert!(
            h.fs.calls().iter().all(|p| !p.starts_with(&outside)),
            "INV-07: the target of a symlink was examined"
        );
        assert!(
            listed.contains(&root)
                && listed.contains(&root.join("app"))
                && listed.contains(&root.join("loop")),
            "the real directories must have been walked, got {listed:?}"
        );
    }

    /// # Design promise
    /// INV-06 / INV-07 / AC-002-11: a rule root the `SafetyGuard` refuses - a symlinked root, a
    /// deny-listed root, a root with `..`, an absolute root outside HOME - makes the rule `refused`
    /// with 0 bytes, is recorded as one `skipped` record with reason `root_refused`, and is **never
    /// listed** (not even the symlink's target).
    ///
    /// # Scenario (Given)
    /// Four rules: `sym` (root `Library/Caches` is a symlink to `/Users/u/Elsewhere`, which holds a
    /// file), `denied` (`Documents`, which holds a file), `dotdot` (`Library/../Documents`), `abs`
    /// (`/tmp/other`, absolute, outside HOME, holding a file).
    ///
    /// # Action (When)
    /// `run_scan` with the four rules.
    ///
    /// # Expected (Then)
    /// Each rule: status `refused`, 0 bytes, 0 items; exactly four `skipped` audit records with
    /// reason `root_refused`; `read_dir` was never called; `exit_code() == 4`.
    ///
    /// # Must never
    /// List `/Users/u/Documents`, `/Users/u/Elsewhere` or `/tmp/other`; join an absolute root onto
    /// HOME as if it were relative.
    ///
    /// # Would catch
    /// Scanning roots without `admit_root`, `home.join("/tmp/other")` escaping the home directory,
    /// following a symlinked root (a user symlinking `~/.cargo` elsewhere is common).
    ///
    /// # Why this test (not redundant)
    /// The only enforcement test of root admission at scan time; AC-002-11's table test only proves
    /// the built-in data is admissible.
    #[test]
    fn ac_002_11_roots_refused_by_the_guard_are_never_listed() {
        // Arrange
        let fs = FakeFs::builder()
            .file_sized(home("Elsewhere/data"), 4096, blocks(4096))
            .dir(home("Library"))
            .symlink(home("Library/Caches"), "/Users/u/Elsewhere")
            .file_sized(home("Documents/secret"), 4096, blocks(4096))
            .file_sized("/tmp/other/f", 4096, blocks(4096))
            .build();
        let h = harness(fs);
        let rules = [
            safe("sym", &["Library/Caches"]),
            safe("denied", &["Documents"]),
            safe("dotdot", &["Library/../Documents"]),
            safe("abs", &["/tmp/other"]),
        ];

        // Act
        let report = h.scan(&rules, 5);

        // Assert
        for id in ["sym", "denied", "dotdot", "abs"] {
            let r = rule_report(&report, id);
            assert_eq!(
                r.status.as_str(),
                "refused",
                "{id}: the guard refuses this root"
            );
            assert_eq!((r.bytes, r.items), (0, 0), "{id}: nothing may be counted");
        }
        assert!(
            h.fs.read_dir_calls().is_empty(),
            "INV-06/07: a refused root must never be listed, got {:?}",
            h.fs.read_dir_calls()
        );
        let refused = h
            .records()
            .iter()
            .filter(
                |d| matches!(&d.record, Record::Skipped { reason, .. } if reason == "root_refused"),
            )
            .count();
        assert_eq!(
            refused, 4,
            "one `root_refused` skipped record per refused root"
        );
        assert_eq!(report.exit_code(), 4, "a refused root is a partial result");
    }

    /// # Design promise
    /// AC-002-6 / INV-08: a directory on a different device than its rule root is not listed or
    /// descended; it is recorded as `skipped{reason: "cross_device"}`. The root's own device is the
    /// baseline, so a root that is itself a mount point is scanned normally.
    ///
    /// # Scenario (Given)
    /// Rule `caches` (device 1): `f1` (4 KiB), `app/ok` (4 KiB), a mount `mnt` (device 2) holding a
    /// 1 MiB file, and a nested mount `app/deep/vol` (device 3) holding a file. Rule `mounted`, whose
    /// root `Mounted` is itself on device 2, holds two 4 KiB files.
    ///
    /// # Action (When)
    /// `run_scan` with both rules.
    ///
    /// # Expected (Then)
    /// `caches`: 8192 bytes, `skipped == 2` with `{cross_device: 2}`, `read_dir` never called on `mnt`
    /// or `vol`; two audit `skipped` records (`/Users/u/Library/Caches/mnt` and `.../app/deep/vol`) with
    /// reason `cross_device`. `mounted`: 8192 bytes, `skipped == 0`.
    ///
    /// # Must never
    /// List another device (it could be a network or backup volume); treat the root's own device as
    /// foreign.
    ///
    /// # Would catch
    /// Missing `st_dev` comparison, comparing against HOME's device instead of the root's, only
    /// checking direct children (the nested mount), skipping silently without a record.
    ///
    /// # Why this test (not redundant)
    /// The only scan-level device test (the guard's `CrossDevice` is spec 001, a different code path).
    #[test]
    fn ac_002_6_a_directory_on_another_device_is_not_entered_and_is_reported() {
        // Arrange
        let c = home("Library/Caches");
        let fs = FakeFs::builder()
            .file_sized(c.join("f1"), 4096, blocks(4096))
            .file_sized(c.join("app/ok"), 4096, blocks(4096))
            .file_sized(c.join("mnt/big"), KIB * KIB, blocks(KIB * KIB))
            .dev(c.join("mnt"), 2)
            .file_sized(c.join("app/deep/vol/x"), 4096, blocks(4096))
            .dev(c.join("app/deep/vol"), 3)
            .file_sized(home("Mounted/y"), 4096, blocks(4096))
            .file_sized(home("Mounted/z"), 4096, blocks(4096))
            .dev(home("Mounted"), 2)
            .build();
        let h = harness(fs);

        // Act
        let report = h.scan(
            &[
                safe("caches", &["Library/Caches"]),
                safe("mounted", &["Mounted"]),
            ],
            5,
        );

        // Assert
        let caches = rule_report(&report, "caches");
        assert_eq!(
            caches.bytes, 8192,
            "INV-08: nothing from the other devices may be counted"
        );
        assert_eq!(caches.skipped, 2, "both foreign mounts are skips");
        assert_eq!(
            caches.skipped_by_reason,
            BTreeMap::from([("cross_device".to_owned(), 2)]),
            "skips are tallied by reason"
        );
        let listed = h.fs.read_dir_calls();
        assert!(
            !listed.contains(&c.join("mnt")) && !listed.contains(&c.join("app/deep/vol")),
            "INV-08: a directory on another device was listed: {listed:?}"
        );
        let skipped: BTreeSet<PathBuf> = h
            .records()
            .into_iter()
            .filter_map(|d| match d.record {
                Record::Skipped { path, reason } if reason == "cross_device" => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(
            skipped,
            BTreeSet::from([c.join("mnt"), c.join("app/deep/vol")]),
            "audit must hold one cross_device skip per foreign mount, with its path"
        );
        let mounted = rule_report(&report, "mounted");
        assert_eq!(
            (mounted.bytes, mounted.skipped),
            (8192, 0),
            "a root on its own device is the baseline"
        );
    }

    /// # Design promise
    /// AC-002-7 / INV-09 / INV-10: an entry that cannot be read (`EPERM`/`EACCES` on `lstat` or on
    /// listing a directory) is skipped with reason `permission_denied`, logged with its path, the
    /// walk continues with its siblings, the rule becomes `partial` (exit 4), and the entry is tried
    /// **once** (no retry, no escalation). Any other I/O error is also a skip (`io_error`).
    ///
    /// # Scenario (Given)
    /// Rows: `lstat` EPERM on a file; `lstat` EACCES on a file; `lstat` EPERM on a directory;
    /// `read_dir` EPERM on a directory (macOS TCC); `read_dir` EACCES on a directory; `lstat` EIO on a
    /// file (reason `io_error`, **an assumption beyond the spec**, see the matrix). Next to the
    /// locked entry sit `a.bin` and `z.bin` (4096 each); a locked directory also holds a file that
    /// must not be counted.
    ///
    /// # Action (When)
    /// `run_scan` per row.
    ///
    /// # Expected (Then)
    /// `bytes == 8192`, `items == 2`, status `partial`, `skipped == 1` with `{reason: 1}`, exactly one
    /// audit `skipped` record for the locked path with that reason, `exit_code() == 4`; the locked
    /// path was passed to `lstat`/`read_dir` at most once; the runner never saw `sudo`.
    ///
    /// # Must never
    /// Abort the walk; retry; escalate; count the unreadable directory's contents.
    ///
    /// # Would catch
    /// `?`-propagating the first error, a retry loop, silently ignoring errors (rule shown `ok` with
    /// a too-small number), classifying EPERM as vanished, forgetting to set `partial`.
    ///
    /// # Why this test (not redundant)
    /// The only test of the permission/I-O error class (INV-09); vanishing (ENOENT) is separate.
    #[test]
    fn ac_002_7_unreadable_entries_are_skipped_once_logged_and_the_walk_continues() {
        // Arrange
        #[derive(Clone, Copy)]
        enum Fault {
            Lstat(i32),
            List(i32),
        }
        let rows = [
            (
                "lstat EPERM on file",
                false,
                Fault::Lstat(1),
                "permission_denied",
            ),
            (
                "lstat EACCES on file",
                false,
                Fault::Lstat(13),
                "permission_denied",
            ),
            (
                "lstat EPERM on dir",
                true,
                Fault::Lstat(1),
                "permission_denied",
            ),
            (
                "read_dir EPERM on dir (TCC)",
                true,
                Fault::List(1),
                "permission_denied",
            ),
            (
                "read_dir EACCES on dir",
                true,
                Fault::List(13),
                "permission_denied",
            ),
            ("lstat EIO on file", false, Fault::Lstat(5), "io_error"),
        ];
        let root = home("Library/Caches");
        let locked = root.join("locked");

        for (name, is_dir, fault, reason) in rows {
            let mut b = FakeFs::builder()
                .file_sized(root.join("a.bin"), 4096, blocks(4096))
                .file_sized(root.join("z.bin"), 4096, blocks(4096));
            b = if is_dir {
                b.file_sized(locked.join("inside"), 4096, blocks(4096))
            } else {
                b.file_sized(&locked, 4096, blocks(4096))
            };
            b = match fault {
                Fault::Lstat(e) => b.error_at(&locked, e),
                Fault::List(e) => b.list_error_at(&locked, e),
            };
            let h = harness(b.build());

            // Act
            let report = h.scan(&[safe("user-caches", &["Library/Caches"])], 5);

            // Assert
            let r = rule_report(&report, "user-caches");
            assert_eq!(
                (r.bytes, r.items),
                (8192, 2),
                "{name}: siblings counted, locked contents not"
            );
            assert_eq!(
                r.status.as_str(),
                "partial",
                "{name}: unseen entries make the rule partial"
            );
            assert_eq!(r.skipped, 1, "{name}: exactly one skip");
            assert_eq!(
                r.skipped_by_reason,
                BTreeMap::from([(reason.to_owned(), 1)]),
                "{name}: skip reason"
            );
            let logged: Vec<(PathBuf, String)> = h
                .records()
                .into_iter()
                .filter_map(|d| match d.record {
                    Record::Skipped { path, reason } => Some((path, reason)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                logged,
                vec![(locked.clone(), reason.to_owned())],
                "{name}: one skipped record naming the path and the reason"
            );
            assert_eq!(
                report.exit_code(),
                4,
                "{name}: INV-09 skipped entries exit 4"
            );
            let attempts = |calls: Vec<PathBuf>| calls.iter().filter(|p| **p == locked).count();
            assert!(
                attempts(h.fs.calls()) <= 1 && attempts(h.fs.read_dir_calls()) <= 1,
                "{name}: INV-09/10 the entry must be tried once, never retried"
            );
            assert!(
                h.runner.calls().iter().all(|c| !c.program.contains("sudo")),
                "{name}: INV-10 no privilege escalation"
            );
        }
    }

    /// # Design promise
    /// AC-002-7 / INV-09 / the ratified root-permission rule (spec 002, "Permission on the root itself"): when `lstat` of a rule
    /// **root** fails with `EACCES`/`EPERM` (the typical TCC-protected `ios-backups`), the rule is
    /// `partial` - bytes 0, exactly one `skipped{permission_denied}` - and **not** `refused`.
    /// `refused` stays reserved for guard verdicts (deny list, symlinked root) and for any *other*
    /// I/O error on the root (`EIO`), which are fail-closed. A denied root never fails the rule's
    /// other roots.
    ///
    /// # Scenario (Given)
    /// Rows (one rule over `Library/Application Support/MobileSync/Backup`, the real `ios-backups`
    /// root, unless stated): `lstat` EACCES on the root; `lstat` EPERM on the root; `lstat` EIO on the
    /// root; two-root rule `[Locked, Open]` with EACCES on `Locked` and one 4 KiB file in `Open`; a
    /// deny-listed root (`Documents`) that **also** returns EACCES; a symlinked root (no injected
    /// error).
    ///
    /// # Action (When)
    /// `run_scan` per row.
    ///
    /// # Expected (Then)
    /// EACCES/EPERM: status `partial`, `bytes == 0`, one audit `skipped` record `permission_denied`
    /// naming the root, `exit_code() == 4`. EIO: `refused`, one `root_refused` record, exit 4.
    /// Two-root row: `partial`, 4096 bytes, 1 item, one `permission_denied` record. Deny-listed and
    /// symlinked rows: `refused` with one `root_refused` record (the guard verdict beats the errno).
    /// In every row nothing below the unreadable/refused root is listed.
    ///
    /// # Must never
    /// Report a TCC-protected root as `refused` (the user would be told the rule is unsafe instead of
    /// "grant Full Disk Access"); count bytes of an unreadable root; let a permission error on one
    /// root hide the other roots; downgrade a deny-listed or symlinked root to "permission denied";
    /// retry or escalate.
    ///
    /// # Would catch
    /// Mapping every non-ENOENT `Io` from `admit_root` to `refused`; treating EIO like EACCES (an
    /// ambiguous failure must stay fail-closed); letting the errno override a guard verdict.
    ///
    /// # Why this test (not redundant)
    /// Pins the root-level permission rule that `ac_002_7` (entries below the root) and
    /// `ac_002_11_roots_refused` (guard verdicts only) do not reach.
    #[test]
    #[allow(clippy::too_many_lines, reason = "table rows")]
    fn ac_002_7_root_permission_error_is_partial_other_root_errors_and_verdicts_stay_refused() {
        // Arrange
        struct Row {
            name: &'static str,
            fs: FakeFs,
            roots: Vec<&'static str>,
            status: &'static str,
            bytes: u64,
            reason: &'static str,
        }
        let backup = "Library/Application Support/MobileSync/Backup";
        let rows = vec![
            Row {
                name: "root lstat EACCES",
                fs: FakeFs::builder()
                    .file_sized(home(backup).join("dev/Manifest.db"), 4096, blocks(4096))
                    .error_at(home(backup), 13)
                    .build(),
                roots: vec![backup],
                status: "partial",
                bytes: 0,
                reason: "permission_denied",
            },
            Row {
                name: "root lstat EPERM (TCC)",
                fs: FakeFs::builder()
                    .file_sized(home(backup).join("dev/Manifest.db"), 4096, blocks(4096))
                    .error_at(home(backup), 1)
                    .build(),
                roots: vec![backup],
                status: "partial",
                bytes: 0,
                reason: "permission_denied",
            },
            Row {
                name: "root lstat EIO stays fail-closed",
                fs: FakeFs::builder()
                    .file_sized(home(backup).join("dev/Manifest.db"), 4096, blocks(4096))
                    .error_at(home(backup), 5)
                    .build(),
                roots: vec![backup],
                status: "refused",
                bytes: 0,
                reason: "root_refused",
            },
            Row {
                name: "one denied root, one readable root",
                fs: FakeFs::builder()
                    .file_sized(home("Locked/x"), 4096, blocks(4096))
                    .error_at(home("Locked"), 13)
                    .file_sized(home("Open/y"), 4096, blocks(4096))
                    .build(),
                roots: vec!["Locked", "Open"],
                status: "partial",
                bytes: 4096,
                reason: "permission_denied",
            },
            Row {
                name: "deny-listed root that also gives EACCES: the verdict wins",
                fs: FakeFs::builder()
                    .file_sized(home("Documents/secret"), 4096, blocks(4096))
                    .error_at(home("Documents"), 13)
                    .build(),
                roots: vec!["Documents"],
                status: "refused",
                bytes: 0,
                reason: "root_refused",
            },
            Row {
                name: "symlinked root",
                fs: FakeFs::builder()
                    .file_sized(home("Elsewhere/data"), 4096, blocks(4096))
                    .symlink(home("Linked"), home("Elsewhere"))
                    .build(),
                roots: vec!["Linked"],
                status: "refused",
                bytes: 0,
                reason: "root_refused",
            },
        ];

        for row in rows {
            let h = harness(row.fs);
            let rule = safe("root-perm", &row.roots);

            // Act
            let report = h.scan(std::slice::from_ref(&rule), 5);

            // Assert
            let r = rule_report(&report, "root-perm");
            assert_eq!(
                r.status.as_str(),
                row.status,
                "{}: rule status (ratified root-permission rule: permission => partial, verdict/EIO => refused)",
                row.name
            );
            assert_eq!(r.bytes, row.bytes, "{}: bytes counted", row.name);
            let skips: Vec<String> = h
                .records()
                .into_iter()
                .filter_map(|d| match d.record {
                    Record::Skipped { reason, .. } => Some(reason),
                    _ => None,
                })
                .collect();
            assert_eq!(
                skips,
                vec![row.reason.to_owned()],
                "{}: exactly one skipped record with the right reason",
                row.name
            );
            assert_eq!(r.skipped, 1, "{}: one skip tallied", row.name);
            assert_eq!(
                report.exit_code(),
                4,
                "{}: partial/refused exit 4",
                row.name
            );
            let blocked = [
                home(backup),
                home("Locked"),
                home("Documents"),
                home("Elsewhere"),
                home("Linked"),
            ];
            assert!(
                h.fs.read_dir_calls()
                    .iter()
                    .all(|p| !blocked.iter().any(|b| p.starts_with(b))),
                "{}: nothing below an unreadable or refused root may be listed: {:?}",
                row.name,
                h.fs.read_dir_calls()
            );
        }
    }

    /// # Design promise
    /// AC-002-22: subtrees matching a rule's `excludes` contribute 0 to that rule (matching is
    /// component-wise, so look-alike names are not excluded) - the tool's own logs are never reported
    /// as reclaimable.
    ///
    /// # Scenario (Given)
    /// Rule `user-logs`-like: root `Library/Logs`, excludes `Library/Logs/mac-cleaner` and
    /// `Library/Logs/mac-cleaner-dev`. Files (4096 each): `a.log`, `mac-cleaner/audit.jsonl`,
    /// `mac-cleaner/sub/deep`, `mac-cleaner-dev/x`, `mac-cleaner-extra/y`, `mac-cleaner.txt`.
    ///
    /// # Action (When)
    /// `run_scan`.
    ///
    /// # Expected (Then)
    /// `bytes == 12288`, `items == 3`: `a.log`, `mac-cleaner-extra/y` and `mac-cleaner.txt` only.
    ///
    /// # Must never
    /// Count anything below the two excluded directories; exclude the look-alikes.
    ///
    /// # Would catch
    /// Ignoring excludes, string-prefix matching (`mac-cleaner-extra` and `mac-cleaner.txt` lost),
    /// excluding only the first level (the nested file counted).
    ///
    /// # Why this test (not redundant)
    /// The only scan-level excludes test; claim logic for excludes is unit-tested in `rules_table.rs`.
    #[test]
    fn ac_002_22_excluded_subtrees_contribute_nothing_and_lookalikes_do_count() {
        // Arrange
        let l = home("Library/Logs");
        let mut b = FakeFs::builder();
        for rel in [
            "a.log",
            "mac-cleaner/audit.jsonl",
            "mac-cleaner/sub/deep",
            "mac-cleaner-dev/x",
            "mac-cleaner-extra/y",
            "mac-cleaner.txt",
        ] {
            b = b.file_sized(l.join(rel), 4096, blocks(4096));
        }
        let h = harness(b.build());
        let mut rule = safe("user-logs", &["Library/Logs"]);
        rule.excludes = vec![
            "Library/Logs/mac-cleaner".into(),
            "Library/Logs/mac-cleaner-dev".into(),
        ];

        // Act
        let report = h.scan(&[rule], 5);

        // Assert
        let r = rule_report(&report, "user-logs");
        assert_eq!(
            r.bytes, 12_288,
            "AC-002-22: only a.log, mac-cleaner-extra/y and mac-cleaner.txt count"
        );
        assert_eq!(r.items, 3, "excluded subtrees contribute no items either");
    }

    /// # Design promise
    /// AC-002-9 / INV-12: nested roots are claimed by the most specific rule; a parent rule's total
    /// excludes the claimed subtree; the rules' sum equals the bytes of the union of roots; the
    /// result does not depend on rule order; a sibling that merely shares a name prefix
    /// (`Caches-old`) is outside every root.
    ///
    /// # Scenario (Given)
    /// Rules `P` (`Library/Caches`), `C` (`Library/Caches/Homebrew`), `D`
    /// (`Library/Caches/Homebrew/downloads`). Files: `Caches/a` 4096; `Homebrew/b` 8192;
    /// `downloads/c` 12288; `Caches-old/x` 4096 (under no root).
    ///
    /// # Action (When)
    /// Scan in order `[P, C, D]` and in order `[D, C, P]`.
    ///
    /// # Expected (Then)
    /// In both orders: `P == 4096`, `C == 8192`, `D == 12288` bytes (1 item each) and the three sum to
    /// 24576 = bytes of the union of the roots (no double counting, `Caches-old` excluded).
    ///
    /// # Must never
    /// Count a file under two rules; let rule order change who owns a nested subtree.
    ///
    /// # Would catch
    /// A parent walk that does not skip claimed subtrees (Homebrew counted in both, ~2x), ownership by
    /// rule order instead of specificity, string-prefix roots.
    ///
    /// # Why this test (not redundant)
    /// The example-based nesting test; the property test below generalizes the sum invariant, and
    /// `owner_of` is unit-tested separately.
    #[test]
    fn ac_002_9_nested_roots_are_claimed_by_the_most_specific_rule_without_double_counting() {
        // Arrange
        let c = home("Library/Caches");
        let fs = FakeFs::builder()
            .file_sized(c.join("a"), 4096, blocks(4096))
            .file_sized(c.join("Homebrew/b"), 8192, blocks(8192))
            .file_sized(c.join("Homebrew/downloads/c"), 12_288, blocks(12_288))
            .file_sized(home("Library/Caches-old/x"), 4096, blocks(4096))
            .build();
        let h = harness(fs);
        let p = safe("P", &["Library/Caches"]);
        let cc = safe("C", &["Library/Caches/Homebrew"]);
        let d = safe("D", &["Library/Caches/Homebrew/downloads"]);

        for (label, rules) in [
            ("[P, C, D]", [p.clone(), cc.clone(), d.clone()]),
            ("[D, C, P]", [d, cc, p]),
        ] {
            // Act
            let report = h.scan(&rules, 5);

            // Assert
            let bytes = |id: &str| rule_report(&report, id).bytes;
            assert_eq!(
                bytes("P"),
                4096,
                "{label}: parent excludes the claimed subtrees"
            );
            assert_eq!(bytes("C"), 8192, "{label}: C owns Homebrew minus downloads");
            assert_eq!(
                bytes("D"),
                12_288,
                "{label}: the most specific rule owns downloads"
            );
            assert_eq!(
                bytes("P") + bytes("C") + bytes("D"),
                24_576,
                "{label}: INV-12 sum of rules == bytes of the union of roots"
            );
        }
    }

    use proptest::prelude::*;

    proptest! {
        // No on-disk regression file: failures print their minimal input (tests never write into
        // the source tree, INV-15 spirit).
        #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, ..ProptestConfig::default() })]

        /// # Design promise
        /// AC-002-9 / INV-12: for any tree, any set of (possibly nested, possibly absent) roots and
        /// any hardlinks, the sum of all rules' bytes (and items) equals the bytes (items) of the
        /// union of the roots counting each inode once - nothing counted twice, nothing lost.
        ///
        /// # Scenario (Given)
        /// A random tree under `/Users/u/R` (dirs `d0..d2` up to depth 3, files `f0..f2`, files
        /// optionally in one of three hardlink groups sharing inode and size) and 1..4 random rules,
        /// each with one root `R/<dirs>` (so roots nest, coincide-by-prefix, or do not exist).
        ///
        /// # Action (When)
        /// `run_scan`; compare with an oracle computed from the generated model alone (files under any
        /// root, distinct inodes).
        ///
        /// # Expected (Then)
        /// `sum(rule.bytes) == oracle bytes` and `sum(rule.items) == oracle items`.
        ///
        /// # Must never
        /// Count a file under two rules, or an inode twice, or drop a file under some root.
        ///
        /// # Would catch
        /// Parent/child double counting, ownership holes (a file under no rule's walk), dedupe that
        /// only works within one rule.
        ///
        /// # Why this test (not redundant)
        /// The spec asks for the sum invariant; the example tests fix specific shapes, this explores
        /// the nesting x hardlink x absent-root combinations.
        #[test]
        fn ac_002_9_property_rule_sums_equal_the_union_of_roots(
            specs in prop::collection::vec(
                (prop::collection::vec(0u8..3, 0..3), 0u8..3, prop::option::of(0u8..3)),
                0..12,
            ),
            root_specs in prop::collection::vec(prop::collection::vec(0u8..3, 0..3), 1..4),
        ) {
            // Model: last spec wins per path.
            let mut files: BTreeMap<PathBuf, (Option<u8>, usize)> = BTreeMap::new();
            for (idx, (dirs, name, group)) in specs.iter().enumerate() {
                let mut p = PathBuf::from("/Users/u/R");
                for d in dirs { p.push(format!("d{d}")); }
                p.push(format!("f{name}"));
                files.insert(p, (*group, idx));
            }
            let group_size = |g: u8| {
                u32::try_from(files.values().filter(|(x, _)| *x == Some(g)).count()).unwrap_or(u32::MAX)
            };
            let mut b = FakeFs::builder().dir("/Users/u/R");
            for (path, (group, idx)) in &files {
                let (ino, blk) = match group {
                    Some(g) => (5000 + u64::from(*g), 8 * (1 + u64::from(*g))),
                    None => (6000 + *idx as u64, 8 * (5 + *idx as u64)),
                };
                let nlink = group.map_or(1, group_size);
                b = b.file_sized(path, blk * 512, blk).ino(path, ino, nlink);
            }
            let mut root_set: BTreeSet<PathBuf> = BTreeSet::new();
            for dirs in &root_specs {
                let mut r = PathBuf::from("R");
                for d in dirs { r.push(format!("d{d}")); }
                root_set.insert(r);
            }
            let rules: Vec<Rule> = root_set
                .iter()
                .enumerate()
                .map(|(i, r)| safe(&format!("r{i}"), &[r.to_str().expect("utf-8 root")]))
                .collect();

            // Oracle: distinct inodes among files under any root.
            let mut inodes: BTreeMap<u64, u64> = BTreeMap::new();
            for (path, (group, idx)) in &files {
                let under = root_set.iter().any(|r| path.starts_with(Path::new("/Users/u").join(r)));
                if under {
                    let (ino, blk) = match group {
                        Some(g) => (5000 + u64::from(*g), 8 * (1 + u64::from(*g))),
                        None => (6000 + *idx as u64, 8 * (5 + *idx as u64)),
                    };
                    inodes.insert(ino, blk * 512);
                }
            }
            let want_bytes: u64 = inodes.values().sum();
            let want_items = inodes.len() as u64;

            let report = harness(b.build()).scan(&rules, 0);

            let got_bytes: u64 = report.rules.iter().map(|r| r.bytes).sum();
            let got_items: u64 = report.rules.iter().map(|r| r.items).sum();
            prop_assert_eq!(got_bytes, want_bytes, "sum of rule bytes must equal the union of roots; roots={:?}", root_set);
            prop_assert_eq!(got_items, want_items, "sum of rule items must equal distinct inodes under the roots");
        }
    }
}
