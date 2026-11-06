//! Audit file naming and retention (spec 001 AC-001-14; INV-11, INV-13). The real directory
//! adapter (`FileLogStore`) is tested in `cleaner-macos/tests/safety_log_store.rs`.
//!
//! # Worksheet 1 - `audit::audit_file_name`
//! ```text
//! Function:        audit_file_name(SystemTime) -> String
//! Contract:        `audit-YYYY-MM-DD.jsonl` of the UTC date of the instant. (AC-001-14)
//! Equivalence classes: mid-day | last second of a day | first second of next day | leap day |
//!                  year rollover
//! Boundaries:      23:59:59Z / 00:00:00Z; 2024-02-29; 2025-12-31 / 2026-01-01
//! Must-never:      using local time (would shift the day near midnight UTC)
//! Selected tests:  ac_001_14_daily_file_name_follows_the_utc_date_of_the_instant (one table)
//! Deliberately not tested: pre-epoch (covered by the ts clamp in audit_log.rs).
//! ```
//!
//! # Worksheet 2 - `audit::prune`
//! ```text
//! Function:        prune(&dyn LogStore, &dyn Clock, retain_days) -> Result<Vec<String>>
//! Contract:        removes exactly the files named `audit-YYYY-MM-DD.jsonl` (valid calendar date)
//!                  whose date is MORE than retain_days before today's UTC date (exactly
//!                  retain_days old is kept); never the newest audit file; never any other name;
//!                  returns removed names ascending. (AC-001-14)
//! Equivalence classes: older than cutoff | exactly at cutoff | newer | non-audit names (diag log,
//!                  notes, .bak suffix, bad date, non-padded date, dotfile) | newest-is-old
//! Boundaries:      91 vs 90 days old; single old file; two old files
//! Must-never:      remove a non-audit file; remove the newest audit file; remove at the boundary
//! Selected tests:  ac_001_14_prune_removes_only_audit_files_older_than_the_cutoff,
//!                  ac_001_14_prune_never_removes_the_newest_audit_file
//! Deliberately not tested: remove() failure policy (unspecified; see matrix open issues).
//! ```

use std::time::UNIX_EPOCH;

use cleaner_core::audit::{audit_file_name, prune};
use cleaner_core::ports::Clock;
use cleaner_testkit::{FixedClock, MemoryLogStore};

/// # Design promise
/// AC-001-14: the daily file name is derived from the UTC date of the injected clock.
///
/// # Scenario (Given)
/// Instants: 2026-11-06T12:34:56Z, 2026-11-06T23:59:59Z, 2026-11-07T00:00:00Z, leap day
/// 2024-02-29T00:00:00Z, 2025-12-31T23:59:59Z, 2026-01-01T00:00:00Z; calendar edges: the non-leap
/// century 2100 (`02-28` and `03-01`, no Feb 29), the 400-year leap day 2400-02-29, 2399-12-31, the
/// first second past `i32::MAX` (2038-01-19T03:14:08Z) and the far future 9999-12-31T23:59:59Z.
///
/// # Action (When)
/// `audit_file_name(instant)`.
///
/// # Expected (Then)
/// `audit-2026-11-06.jsonl` (twice), `audit-2026-11-07.jsonl`, `audit-2024-02-29.jsonl`,
/// `audit-2025-12-31.jsonl`, `audit-2026-01-01.jsonl`, and the same date as the input for each
/// calendar-edge instant (`audit-2100-03-01.jsonl` in particular: 2100 has no Feb 29).
///
/// # Must never
/// Use local time or round to the wrong day at the UTC boundary.
///
/// # Would catch
/// Local-timezone date, off-by-one at month/leap-year/year boundaries, missing zero padding, the
/// "every 4th year" leap rule (2100), a missing 400-year exception (2400), 32-bit overflow.
///
/// # Why this test (not redundant)
/// Only coverage of the file-name format and the day boundary.
#[test]
fn ac_001_14_daily_file_name_follows_the_utc_date_of_the_instant() {
    // Arrange
    let rows = [
        ((2026, 11, 6, 12, 34, 56), "audit-2026-11-06.jsonl"),
        ((2026, 11, 6, 23, 59, 59), "audit-2026-11-06.jsonl"),
        ((2026, 11, 7, 0, 0, 0), "audit-2026-11-07.jsonl"),
        ((2024, 2, 29, 0, 0, 0), "audit-2024-02-29.jsonl"),
        ((2025, 12, 31, 23, 59, 59), "audit-2025-12-31.jsonl"),
        ((2026, 1, 1, 0, 0, 0), "audit-2026-01-01.jsonl"),
        ((2100, 2, 28, 23, 59, 59), "audit-2100-02-28.jsonl"),
        ((2100, 3, 1, 0, 0, 0), "audit-2100-03-01.jsonl"),
        ((2399, 12, 31, 23, 59, 59), "audit-2399-12-31.jsonl"),
        ((2400, 2, 29, 12, 0, 0), "audit-2400-02-29.jsonl"),
        ((2038, 1, 19, 3, 14, 8), "audit-2038-01-19.jsonl"),
        ((9999, 12, 31, 23, 59, 59), "audit-9999-12-31.jsonl"),
    ];

    for ((y, mo, d, h, mi, s), want) in rows {
        // Act
        let clock = FixedClock::at_utc(y, mo, d, h, mi, s);
        let got = audit_file_name(clock.now());

        // Assert
        assert_eq!(
            got, want,
            "{y}-{mo}-{d}T{h}:{mi}:{s}Z must map to the UTC day file"
        );
    }
    assert!(
        FixedClock::at_utc(2026, 11, 6, 0, 0, 0).now() > UNIX_EPOCH,
        "sanity: oracle is post-epoch"
    );
}

/// # Design promise
/// AC-001-14: `prune(retain_days=90)` removes only `audit-*.jsonl` files whose date is more than 90
/// days before today; the boundary day is kept; nothing else in the directory is ever touched.
///
/// # Scenario (Given)
/// Today 2026-11-06T12:00:00Z (cutoff date 2026-08-08, i.e. exactly 90 days old). Store holds:
/// `audit-2020-01-01.jsonl` (old), `audit-2026-08-07.jsonl` (91 days), `audit-2026-08-08.jsonl`
/// (exactly 90), `audit-2026-11-06.jsonl` (today), and decoys: `cleaner-2020-01-01.log`,
/// `notes.txt`, `audit-2020-01-02.jsonl.bak`, `audit-2020-13-45.jsonl` (impossible date),
/// `audit-garbage.jsonl`, `audit-2020-1-3.jsonl` (not zero padded), `.DS_Store`, and decoys with a
/// valid-looking month but an impossible day (all old enough to be removed if wrongly accepted):
/// `audit-2026-02-30.jsonl`, `audit-2026-04-31.jsonl`, `audit-2023-02-29.jsonl` (not a leap year),
/// `audit-1900-02-29.jsonl` (century, not a leap year), `audit-2026-00-10.jsonl` (month 0). Plus two
/// genuine leap days that must be accepted and (being old) removed: `audit-2000-02-29.jsonl`,
/// `audit-2024-02-29.jsonl`.
///
/// # Action (When)
/// `prune(store, clock, 90)`.
///
/// # Expected (Then)
/// Returns (and the store recorded removing) exactly `[audit-2000-02-29.jsonl,
/// audit-2020-01-01.jsonl, audit-2024-02-29.jsonl, audit-2026-08-07.jsonl]`; everything else remains,
/// in particular the 90-day-old boundary file and every impossible-date decoy.
///
/// # Must never
/// Remove a non-audit file, a malformed name, a file at the boundary, or today's file.
///
/// # Would catch
/// `>=` instead of `>` at the cutoff, glob `audit-*` matching `.bak`, parsing garbage dates leniently
/// (no day-of-month / leap-year validation: Feb 30, Apr 31, 1900-02-29), a too-strict parser that
/// rejects real leap days, deleting the diagnostic `cleaner-*.log`.
///
/// # Why this test (not redundant)
/// The only retention table (cutoff boundary + name filter); newest-file protection is next.
#[test]
fn ac_001_14_prune_removes_only_audit_files_older_than_the_cutoff() {
    // Arrange
    let names = [
        "audit-2020-01-01.jsonl",
        "audit-2026-08-07.jsonl",
        "audit-2026-08-08.jsonl",
        "audit-2026-11-06.jsonl",
        "cleaner-2020-01-01.log",
        "notes.txt",
        "audit-2020-01-02.jsonl.bak",
        "audit-2020-13-45.jsonl",
        "audit-garbage.jsonl",
        "audit-2020-1-3.jsonl",
        ".DS_Store",
        "audit-2026-02-30.jsonl",
        "audit-2026-04-31.jsonl",
        "audit-2023-02-29.jsonl",
        "audit-1900-02-29.jsonl",
        "audit-2026-00-10.jsonl",
        "audit-2000-02-29.jsonl",
        "audit-2024-02-29.jsonl",
    ];
    let store = MemoryLogStore::with_names(names);
    let clock = FixedClock::at_utc(2026, 11, 6, 12, 0, 0);

    // Act
    let removed = prune(&store, &clock, 90).expect("memory store never fails");

    // Assert
    let want = vec![
        "audit-2000-02-29.jsonl".to_owned(),
        "audit-2020-01-01.jsonl".to_owned(),
        "audit-2024-02-29.jsonl".to_owned(),
        "audit-2026-08-07.jsonl".to_owned(),
    ];
    assert_eq!(
        removed, want,
        "returned list must be exactly the files older than 90 days"
    );
    assert_eq!(
        store.removed(),
        want,
        "the store must have been asked to remove exactly those"
    );
    let mut expected_remaining: Vec<String> = names
        .iter()
        .filter(|n| !want.iter().any(|w| w == **n))
        .map(|n| (*n).to_owned())
        .collect();
    expected_remaining.sort();
    assert_eq!(
        store.remaining(),
        expected_remaining,
        "no other file may be touched"
    );
}

/// # Design promise
/// AC-001-14 / INV-11: the newest audit file is never removed, even when it is older than the cutoff
/// (a stale log is better than no evidence of the last run).
///
/// # Scenario (Given)
/// Today 2026-11-06. (A) two very old audit files `2020-01-01` and `2020-02-01`; (B) a single very
/// old audit file.
///
/// # Action (When)
/// `prune(.., 90)` on each store.
///
/// # Expected (Then)
/// (A) removes only `audit-2020-01-01.jsonl`, keeping `2020-02-01` (newest); (B) removes nothing.
///
/// # Must never
/// Leave the log directory without any audit file because everything is old.
///
/// # Would catch
/// A pure age filter without the newest-file exemption.
///
/// # Why this test (not redundant)
/// Only coverage of the newest-file exemption (the cutoff table has a newest file that is recent).
#[test]
fn ac_001_14_prune_never_removes_the_newest_audit_file() {
    // Arrange
    let clock = FixedClock::at_utc(2026, 11, 6, 12, 0, 0);
    let two_old = MemoryLogStore::with_names(["audit-2020-02-01.jsonl", "audit-2020-01-01.jsonl"]);
    let one_old = MemoryLogStore::with_names(["audit-2020-01-01.jsonl"]);

    // Act
    let removed_a = prune(&two_old, &clock, 90).expect("memory store never fails");
    let removed_b = prune(&one_old, &clock, 90).expect("memory store never fails");

    // Assert
    assert_eq!(
        removed_a,
        vec!["audit-2020-01-01.jsonl".to_owned()],
        "A: only the older file goes"
    );
    assert_eq!(
        two_old.remaining(),
        vec!["audit-2020-02-01.jsonl".to_owned()],
        "A: newest must remain"
    );
    assert!(
        removed_b.is_empty(),
        "B: the only (hence newest) audit file must never be removed"
    );
    assert_eq!(one_old.remaining().len(), 1, "B: the file is still there");
}

/// # Design promise
/// AC-001-14: the retention cutoff is exact calendar arithmetic, including around the non-leap
/// century 2100, the 400-year leap year 2400, and the far future: a file exactly `retain_days` old
/// is kept, one day older is removed.
///
/// # Scenario (Given)
/// Rows `(today, retain_days, boundary file, one-day-older file)`: 2100-03-01 / 90 (cutoff
/// 2099-12-01, because Feb 2100 has 28 days); 2400-03-01 / 90 (cutoff 2399-12-02, Feb 2400 has 29);
/// 2100-03-01 / 1 (yesterday is 2100-02-28, there is no Feb 29); 2400-03-01 / 1 (yesterday is
/// 2400-02-29); 9999-12-31 / 365 (cutoff 9998-12-31). Each store also holds today's file.
///
/// # Action (When)
/// `prune(store, clock, retain_days)`.
///
/// # Expected (Then)
/// Exactly the one-day-older file is removed; the boundary file and today's file remain.
///
/// # Must never
/// Treat 2100 as a leap year (would shift the cutoff by a day and delete a file that is exactly at
/// the boundary) or miss 2400's leap day (would keep a file one day too long); overflow far dates.
///
/// # Would catch
/// A hand-rolled day count with `year % 4` only, no `% 100` / `% 400` rules, an off-by-one in month
/// lengths, or 32-bit seconds.
///
/// # Why this test (not redundant)
/// The 2026 table cannot see leap-year rules (its window contains no Feb 29); this adds only the
/// calendar-edge rows, one row per rule.
#[test]
fn ac_001_14_prune_cutoff_is_exact_across_leap_year_edges() {
    // Arrange
    type Row = (
        (i64, i64, i64),
        u32,
        &'static str,
        &'static str,
        &'static str,
    );
    let rows: [Row; 5] = [
        (
            (2100, 3, 1),
            90,
            "audit-2099-12-01.jsonl",
            "audit-2099-11-30.jsonl",
            "audit-2100-03-01.jsonl",
        ),
        (
            (2400, 3, 1),
            90,
            "audit-2399-12-02.jsonl",
            "audit-2399-12-01.jsonl",
            "audit-2400-03-01.jsonl",
        ),
        (
            (2100, 3, 1),
            1,
            "audit-2100-02-28.jsonl",
            "audit-2100-02-27.jsonl",
            "audit-2100-03-01.jsonl",
        ),
        (
            (2400, 3, 1),
            1,
            "audit-2400-02-29.jsonl",
            "audit-2400-02-28.jsonl",
            "audit-2400-03-01.jsonl",
        ),
        (
            (9999, 12, 31),
            365,
            "audit-9998-12-31.jsonl",
            "audit-9998-12-30.jsonl",
            "audit-9999-12-31.jsonl",
        ),
    ];

    for ((y, mo, d), retain, boundary, older, today) in rows {
        let store = MemoryLogStore::with_names([boundary, older, today]);
        let clock = FixedClock::at_utc(y, mo, d, 12, 0, 0);

        // Act
        let removed = prune(&store, &clock, retain).expect("memory store never fails");

        // Assert
        assert_eq!(
            removed,
            vec![older.to_owned()],
            "{y}-{mo}-{d} retain {retain}: only the file one day past the cutoff may go"
        );
        assert_eq!(
            store.remaining(),
            vec![boundary.to_owned(), today.to_owned()],
            "{y}-{mo}-{d} retain {retain}: boundary and today's file must remain"
        );
    }
}
