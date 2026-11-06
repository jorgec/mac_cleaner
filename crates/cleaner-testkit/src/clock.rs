//! Deterministic `Clock` and `RunIds`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cleaner_core::ports::{Clock, RunId, RunIds};

/// A clock frozen at a chosen instant that only moves when the test says so
/// ([`FixedClock::advance_secs`], [`FixedClock::set_unix_secs`]). Share it as `Arc<FixedClock>`.
#[derive(Debug)]
pub struct FixedClock {
    now: Mutex<SystemTime>,
}

/// Instant `secs` seconds after (or, if negative, before) the Unix epoch.
fn from_unix(secs: i64) -> SystemTime {
    let magnitude = Duration::from_secs(secs.unsigned_abs());
    if secs >= 0 {
        UNIX_EPOCH + magnitude
    } else {
        UNIX_EPOCH - magnitude
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian civil date (H. Hinnant's `days_from_civil`).
/// Deliberately the *inverse* of whatever the implementation under test uses to format dates, so
/// the tests have an independent oracle.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

impl FixedClock {
    /// Frozen at `secs` seconds since the Unix epoch (negative = before the epoch).
    #[must_use]
    pub fn from_unix_secs(secs: i64) -> Self {
        Self {
            now: Mutex::new(from_unix(secs)),
        }
    }

    /// Frozen at the given UTC civil date-time.
    #[must_use]
    pub fn at_utc(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> Self {
        let days = days_from_civil(year, month, day);
        Self::from_unix_secs(days * 86_400 + hour * 3_600 + min * 60 + sec)
    }

    /// Move the clock forward by `secs` seconds.
    ///
    /// # Panics
    /// If the internal lock is poisoned (a previous test thread panicked while holding it).
    pub fn advance_secs(&self, secs: u64) {
        let mut now = self.now.lock().expect("clock lock");
        *now += Duration::from_secs(secs);
    }

    /// Jump to `secs` seconds since the Unix epoch.
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    pub fn set_unix_secs(&self, secs: i64) {
        *self.now.lock().expect("clock lock") = from_unix(secs);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().expect("clock lock")
    }
}

/// Run-id generator yielding `RUN-0001`, `RUN-0002`, ... (sortable, deterministic).
#[derive(Debug, Default)]
pub struct SequentialRunIds {
    next: AtomicU64,
}

impl SequentialRunIds {
    /// Counter starts so that the first id is `RUN-0001`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }
}

impl RunIds for SequentialRunIds {
    fn next_run_id(&self) -> RunId {
        let n = self.next.fetch_add(1, Ordering::SeqCst).max(1);
        RunId::new(format!("RUN-{n:04}"))
    }
}
