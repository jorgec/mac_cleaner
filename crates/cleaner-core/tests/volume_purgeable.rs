//! Purgeable-space arithmetic and the volume section of the scan report
//! (spec 002 AC-002-1, AC-002-2, AC-002-3; INV-12, INV-13).
//!
//! # Worksheet - `volume::purgeable`
//! ```text
//! Function:        cleaner_core::volume::purgeable(&VolumeCaps) -> Purgeable{bytes, clamped}
//! Contract:        bytes = max(0, available_important - available), never above `total`, no
//!                  overflow/underflow for any u64; `clamped` is true exactly when the raw
//!                  difference had to be adjusted (negative -> 0, or above total -> total).
//!                  (AC-002-1, INV-12, INV-13)
//! Equivalence classes: I > A (plain difference) | I == A | I < A (clamp to 0) | difference
//!                  above total (cap) | extreme u64 values
//! Boundaries:      I == A -> 0 and NOT clamped; I == A - 1 -> 0 and clamped; I - A == T -> T and
//!                  NOT clamped; I - A == T + 1 -> T and clamped
//! Must-never:      panic or wrap on u64 extremes; report more than `total`; flag a plain
//!                  difference as clamped
//! Selected tests:  ac_002_1_purgeable_is_the_clamped_difference_never_above_total
//! Deliberately not tested: a proptest over all u64 (the table covers each class and boundary,
//!                  including both extremes; an oracle would restate the formula).
//! ```
//!
//! # Worksheet - volume section of `run_scan`
//! ```text
//! Function:        scan::run_scan (volume part)
//! Contract:        queries the volume at the injected HOME exactly once; reports mount_point,
//!                  total, available, available_important, purgeable, purgeable_clamped; a failed
//!                  query yields purgeable = null (never 0) + volume_error = <kind>, the other
//!                  numbers null too, rule scanning still runs, exit code 4; purgeable is never
//!                  added to the reclaimable totals. (AC-002-2, AC-002-3, INV-13)
//! Equivalence classes: query ok (I > A) | query ok (I < A, clamped) | query fails (two kinds)
//! Boundaries:      unknown vs zero (the whole point of INV-13)
//! Must-never:      serialize `purgeable: 0` for an unknown value; skip rule scanning because the
//!                  volume failed; add purgeable bytes into `totals`
//! Selected tests:  ac_002_3_..., ac_002_2_...
//! Deliberately not tested: human "unknown" rendering and exit code plumbing of the process
//!                  (CLI, slice 002b).
//! ```

mod common;

use cleaner_core::ports::{VolumeCaps, VolumeError};
use cleaner_core::rules::{Rule, Tier};
use cleaner_core::volume::purgeable;
use cleaner_testkit::{FakeFs, FakeVolume};
use common::{HOME, blocks, harness, rule_report};

/// A minimal fixture: one Safe rule with one 4 KiB file, so "scanning still ran" is observable.
fn one_file_fs() -> FakeFs {
    FakeFs::builder()
        .file_sized("/Users/u/Library/Caches/a.bin", 4096, blocks(4096))
        .build()
}

fn caches_rule() -> Rule {
    Rule::new("user-caches", Tier::Safe, &["Library/Caches"])
}

/// # Design promise
/// AC-002-1 / INV-12 / INV-13: `purgeable = max(0, important - available)`, never above `total`,
/// computed without overflow; `clamped` flags exactly the cases where the raw difference had to be
/// adjusted.
///
/// # Scenario (Given)
/// Rows `(name, total, available, important, expected_bytes, expected_clamped)`: plain difference;
/// `I == A` (boundary: 0, not clamped); `I == A - 1` (boundary: 0, clamped); `I - A == T` (cap
/// boundary: T, not clamped); `I - A == T + 1` (T, clamped); `I = u64::MAX, A = 0` (extreme high,
/// capped); `I = 0, A = u64::MAX` (extreme low, would underflow).
///
/// # Action (When)
/// `purgeable(&caps)` for each row.
///
/// # Expected (Then)
/// Each row yields exactly its expected `(bytes, clamped)`.
///
/// # Must never
/// Panic or wrap (debug builds panic on u64 overflow/underflow); exceed `total`.
///
/// # Would catch
/// `important - available` without a check (underflow panic or a huge wrapped value),
/// `abs_diff` (reports 1 for I == A - 1), `clamped` computed as `I <= A` (flags the I == A
/// boundary), forgetting the `total` cap.
///
/// # Why this test (not redundant)
/// The only test of the arithmetic; the scanner tests below only check the wiring.
#[test]
fn ac_002_1_purgeable_is_the_clamped_difference_never_above_total() {
    // Arrange
    struct Row {
        name: &'static str,
        total: u64,
        available: u64,
        important: u64,
        want: (u64, bool),
    }
    let rows = [
        Row {
            name: "plain difference",
            total: 500,
            available: 300,
            important: 340,
            want: (40, false),
        },
        Row {
            name: "I == A is zero and not clamped",
            total: 500,
            available: 300,
            important: 300,
            want: (0, false),
        },
        Row {
            name: "I == A - 1 clamps to zero",
            total: 500,
            available: 300,
            important: 299,
            want: (0, true),
        },
        Row {
            name: "I - A == T is exactly total",
            total: 100,
            available: 0,
            important: 100,
            want: (100, false),
        },
        Row {
            name: "I - A == T + 1 is capped",
            total: 100,
            available: 0,
            important: 101,
            want: (100, true),
        },
        Row {
            name: "extreme high is capped at total",
            total: 1000,
            available: 0,
            important: u64::MAX,
            want: (1000, true),
        },
        Row {
            name: "extreme low never underflows",
            total: u64::MAX,
            available: u64::MAX,
            important: 0,
            want: (0, true),
        },
    ];

    for row in rows {
        // Act
        let got = purgeable(&VolumeCaps {
            mount_point: "/".into(),
            total: row.total,
            available: row.available,
            available_important: row.important,
            available_opportunistic: row.available,
        });

        // Assert
        assert_eq!(
            (got.bytes, got.clamped),
            row.want,
            "AC-002-1 row `{}`: (purgeable bytes, clamped) for T={} A={} I={}",
            row.name,
            row.total,
            row.available,
            row.important
        );
    }
}

/// # Design promise
/// AC-002-3 / AC-002-1: the volume is queried at the injected `$HOME`; the report carries
/// `mount_point`, `total`, `available`, `available_important` and `purgeable` (+ the clamp flag);
/// purgeable space is OS-managed and **never added** to the reclaimable totals.
///
/// # Scenario (Given)
/// A healthy fake volume (T=500 GB, A=300 GB, I=304 GB -> 4 GB purgeable) over a fixture with one
/// 4 KiB cache file. Second row: a volume with I < A (clamped).
///
/// # Action (When)
/// `run_scan` with one Safe rule.
///
/// # Expected (Then)
/// Exactly one `query`, at `/Users/u`; the report's volume numbers equal the caps; `purgeable ==
/// Some(4 GB)` and `purgeable_clamped == false` (row 2: `Some(0)`, `true`); `volume_error` is
/// `None`; `totals.safe == 4096` (the rule's bytes only: not 4096 + purgeable).
///
/// # Must never
/// Query another path (e.g. `/`); mix purgeable bytes into `totals`; drop the clamp flag.
///
/// # Would catch
/// Querying `/` instead of HOME (wrong volume on multi-volume Macs), summing purgeable and
/// reclaimable (spec vocabulary: never summed), a report that hard-codes `clamped: false`.
///
/// # Why this test (not redundant)
/// The only success-path wiring test of the volume port; the failure path is the next test.
#[test]
fn ac_002_3_volume_is_queried_at_home_and_purgeable_is_reported_but_never_summed() {
    // Arrange: row 1 healthy, row 2 clamped.
    let rows = [
        ("I > A", 304_000_000_000_u64, Some(4_000_000_000_u64), false),
        ("I < A", 299_000_000_000_u64, Some(0_u64), true),
    ];
    for (name, important, want_purgeable, want_clamped) in rows {
        let h = harness(one_file_fs()).with_volume(FakeVolume::with_numbers(
            "/System/Volumes/Data",
            500_000_000_000,
            300_000_000_000,
            important,
        ));

        // Act
        let report = h.scan(&[caches_rule()], 5);

        // Assert
        assert_eq!(
            h.volume.queries(),
            vec![std::path::PathBuf::from(HOME)],
            "{name}: AC-002-3 the volume must be queried once, at the injected HOME"
        );
        let v = &report.volume;
        assert_eq!(
            v.mount_point.as_deref(),
            Some("/System/Volumes/Data"),
            "{name}: mount_point"
        );
        assert_eq!(v.total, Some(500_000_000_000), "{name}: total");
        assert_eq!(v.available, Some(300_000_000_000), "{name}: available");
        assert_eq!(
            v.available_important,
            Some(important),
            "{name}: available_important"
        );
        assert_eq!(v.purgeable, want_purgeable, "{name}: purgeable");
        assert_eq!(
            v.purgeable_clamped, want_clamped,
            "{name}: purgeable_clamped"
        );
        assert_eq!(v.volume_error, None, "{name}: no error on success");
        assert_eq!(
            report.totals.safe, 4096,
            "{name}: vocabulary - purgeable and reclaimable are never summed; totals.safe must be the rule's own bytes"
        );
    }
}

/// # Design promise
/// AC-002-2 / INV-13: an unknown value is not zero. When the volume query fails the report says
/// `purgeable: null` plus `volume_error: "<kind>"`, the other volume numbers are unknown too,
/// rule scanning still runs, and the exit code is 4.
///
/// # Scenario (Given)
/// A fake volume failing with `PermissionDenied`, and another run failing with `NotFound` (two
/// different kinds, so a constant string would be caught); a healthy fixture with one 4 KiB file.
///
/// # Action (When)
/// `run_scan`, then serialize the report to JSON.
///
/// # Expected (Then)
/// `volume.purgeable == None`, `volume_error == Some(kind)`, `mount_point/total/available/
/// available_important == None`, `purgeable_clamped == false`; the rule still reports 4096 bytes;
/// `exit_code() == 4`; in the JSON `volume.purgeable` is `null` (not the number 0).
///
/// # Must never
/// Serialize `0` for the unknown purgeable value; abort the scan; exit 0.
///
/// # Would catch
/// `unwrap_or(0)` on the query result (the classic "unknown becomes zero" bug), skipping rules when
/// the volume fails, a missing exit-code 4.
///
/// # Why this test (not redundant)
/// The only failure-path test of the volume port (INV-13).
#[test]
fn ac_002_2_unknown_volume_is_null_never_zero_and_scanning_continues() {
    // Arrange
    let rows = [
        (VolumeError::PermissionDenied, "permission_denied"),
        (VolumeError::NotFound { path: HOME.into() }, "not_found"),
    ];
    for (error, kind) in rows {
        let h = harness(one_file_fs()).with_volume(FakeVolume::failing(error));

        // Act
        let report = h.scan(&[caches_rule()], 5);
        let json: serde_json::Value =
            serde_json::to_value(&report).expect("the report must serialize");

        // Assert
        let v = &report.volume;
        assert_eq!(
            v.purgeable, None,
            "{kind}: INV-13 purgeable must be unknown, not 0"
        );
        assert_eq!(
            v.volume_error.as_deref(),
            Some(kind),
            "{kind}: volume_error must carry the kind"
        );
        assert_eq!(
            (
                v.mount_point.as_deref(),
                v.total,
                v.available,
                v.available_important
            ),
            (None, None, None, None),
            "{kind}: the other volume numbers are unknown too"
        );
        assert!(
            !v.purgeable_clamped,
            "{kind}: nothing was clamped when nothing was computed"
        );
        assert!(
            json["volume"]["purgeable"].is_null(),
            "{kind}: AC-002-2 JSON must say `purgeable: null`, got {}",
            json["volume"]["purgeable"]
        );
        assert_eq!(
            rule_report(&report, "user-caches").bytes,
            4096,
            "{kind}: rule scanning must still run when the volume query fails"
        );
        assert_eq!(
            report.exit_code(),
            4,
            "{kind}: unknown volume is a partial result (exit 4)"
        );
    }
}
