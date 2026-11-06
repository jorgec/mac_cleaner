//! `SystemClock`, the production `Clock` (spec 001 INV-11 timestamps, spec 002 age filter).
//!
//! # Worksheet - `SystemClock::now`
//! ```text
//! Function:        cleaner_macos::SystemClock (cleaner_core::ports::Clock)
//! Contract:        now() is the current wall-clock time. (INV-11 `ts`, AC-002-12 `now - min_age`)
//! Equivalence classes: one (a clock has no input)
//! Boundaries:      none (the tolerance below only absorbs scheduling delay)
//! Must-never:      a fixed or epoch time (every audit record would be dated 1970, the age filter
//!                  would treat every file as brand new)
//! Selected tests:  inv_11_system_clock_is_the_current_time
//! Deliberately not tested: monotonicity (wall clocks may step); time zones (UTC instants only).
//! ```

use std::time::{Duration, SystemTime};

use cleaner_core::ports::Clock;
use cleaner_macos::SystemClock;

/// # Design promise
/// INV-11 / AC-002-12: the production clock returns the real current instant, so audit timestamps
/// and file ages are right.
///
/// # Scenario (Given)
/// The OS clock, read just before and just after the call.
///
/// # Action (When)
/// `SystemClock.now()`.
///
/// # Expected (Then)
/// The value lies between the two OS readings (within a 1 s slack for clock granularity).
///
/// # Must never
/// Return the Unix epoch or any constant.
///
/// # Would catch
/// A stub returning `UNIX_EPOCH`, a clock offset by a time-zone shift, seconds/milliseconds mix-ups.
///
/// # Why this test (not redundant)
/// Only test of the production clock; every other test injects a fixed clock.
#[test]
fn inv_11_system_clock_is_the_current_time() {
    // Arrange
    let slack = Duration::from_secs(1);
    let before = SystemTime::now();

    // Act
    let now = SystemClock.now();
    let after = SystemTime::now();

    // Assert
    assert!(
        now + slack >= before && now <= after + slack,
        "SystemClock::now() = {now:?} is not the current time (OS clock {before:?} .. {after:?})"
    );
}
