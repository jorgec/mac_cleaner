//! Sanity test for the `FixedClock` civil-date oracle that audit tests use to build instants.
//!
//! ```text
//! Function:        FixedClock::at_utc / advance_secs
//! Contract:        at_utc(Y,M,D,h,m,s) is the exact UTC instant (independent of the
//!                  implementation's own date formatting, which it is used to check).
//! Equivalence classes: ordinary date; leap day; pre-epoch seconds
//! Boundaries:      1970-01-01T00:00:00Z; 2024-02-29
//! Must-never:      a wrong oracle blaming a correct implementation
//! Selected tests:  at_utc_matches_independently_computed_unix_seconds
//! Deliberately not tested: setters (trivial).
//! ```

use std::time::UNIX_EPOCH;

use cleaner_core::ports::Clock;
use cleaner_testkit::FixedClock;

/// # Design promise
/// `FixedClock::at_utc` equals real Unix time (values computed with `date -u -j -f`).
///
/// # Scenario (Given)
/// 2026-11-06T12:34:56Z (=`1_793_968_496`), the epoch itself, and the leap day 2024-02-29T00:00:00Z
/// (=`1_709_164_800`); the first day after the non-leap century February, 2100-03-01 (=`4_107_542_400`,
/// from Python `calendar.timegm`), and the 400-year leap day 2400-02-29 (=`13_574_563_200`).
///
/// # Action (When)
/// Build `at_utc` clocks and read `now()` as seconds since the epoch; then `advance_secs(4)`.
///
/// # Expected (Then)
/// The five instants equal the reference seconds; advancing adds exactly 4 seconds.
///
/// # Must never
/// n/a
///
/// # Would catch
/// An off-by-one in the days-from-civil arithmetic (leap years, century rules, month offsets); the
/// 2100/2400 rows keep the far-date audit tests from blaming (or trusting) a wrong oracle.
///
/// # Why this test (not redundant)
/// It is the oracle for every timestamp/retention-date assertion in the audit tests.
#[test]
fn at_utc_matches_independently_computed_unix_seconds() {
    // Arrange + Act
    let secs = |c: &FixedClock| {
        c.now()
            .duration_since(UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs()
    };
    let ordinary = FixedClock::at_utc(2026, 11, 6, 12, 34, 56);
    let epoch = FixedClock::at_utc(1970, 1, 1, 0, 0, 0);
    let leap = FixedClock::at_utc(2024, 2, 29, 0, 0, 0);
    let century = FixedClock::at_utc(2100, 3, 1, 0, 0, 0);
    let leap_400 = FixedClock::at_utc(2400, 2, 29, 0, 0, 0);
    let before = secs(&ordinary);
    ordinary.advance_secs(4);

    // Assert
    assert_eq!(
        before, 1_793_968_496,
        "2026-11-06T12:34:56Z reference seconds"
    );
    assert_eq!(secs(&epoch), 0, "epoch reference seconds");
    assert_eq!(
        secs(&century),
        4_107_542_400,
        "2100-03-01 reference seconds (2100 has no Feb 29)"
    );
    assert_eq!(
        secs(&leap_400),
        13_574_563_200,
        "2400-02-29 reference seconds (400-year leap rule)"
    );
    assert_eq!(secs(&leap), 1_709_164_800, "leap-day reference seconds");
    assert_eq!(
        secs(&ordinary),
        1_793_968_500,
        "advance_secs adds exactly the given seconds"
    );
}
