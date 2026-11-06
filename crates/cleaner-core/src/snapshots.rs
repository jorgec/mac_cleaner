//! Local Time Machine snapshots via `tmutil listlocalsnapshots /` (spec 002 AC-002-21).
//! The command is run read-only through the `CommandRunner` port; this module never deletes or
//! thins anything and never uses `sudo` (INV-10).

use std::time::Duration;

use serde::Serialize;

use crate::ports::{CommandError, CommandRunner};

/// Program invoked (absolute path: no `PATH` lookup).
pub const TMUTIL_PROGRAM: &str = "/usr/bin/tmutil";
/// Argument array of the only invocation this module makes.
pub const TMUTIL_ARGS: [&str; 2] = ["listlocalsnapshots", "/"];
/// Timeout passed to the runner.
pub const TMUTIL_TIMEOUT: Duration = Duration::from_secs(10);

/// One line of `tmutil` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// The line as printed (trimmed), e.g. `com.apple.TimeMachine.2026-11-06-123456.local`.
    pub name: String,
    /// Local time of the snapshot as `YYYY-MM-DDTHH:MM:SS` (no zone: the name carries none), or
    /// `None` when the name does not match the documented pattern or is not a real calendar time.
    pub date: Option<String>,
    /// Always `None`: `tmutil` does not report sizes.
    pub bytes: Option<u64>,
}

/// Parsed `tmutil` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSnapshots {
    /// In output order, including lines that did not parse (with `date: None`).
    pub snapshots: Vec<Snapshot>,
    /// How many of `snapshots` have `date: None`.
    pub unparsed: u64,
}

/// Parse the standard output of `tmutil listlocalsnapshots /`.
///
/// Blank lines and the header line (`Snapshots for ...:` e.g. `Snapshots for disk /:`) are not
/// snapshots and are ignored. Every other line is a snapshot named by the trimmed line; its `date`
/// is set only for the exact pattern `com.apple.TimeMachine.<YYYY-MM-DD-HHMMSS>.local` with a real
/// calendar date and time of day (leap years honored, seconds 00..=59). Output order is kept and
/// no size is ever invented (`bytes` is `None`). Pure; never fails.
#[must_use]
pub fn parse_listlocalsnapshots(stdout: &str) -> ParsedSnapshots {
    let snapshots: Vec<Snapshot> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !is_header(line))
        .map(|line| Snapshot {
            name: line.to_owned(),
            date: snapshot_date(line),
            bytes: None,
        })
        .collect();
    let unparsed = snapshots.iter().filter(|s| s.date.is_none()).count() as u64;
    ParsedSnapshots {
        snapshots,
        unparsed,
    }
}

/// `Snapshots for <something>:` (the colon is required).
fn is_header(line: &str) -> bool {
    line.starts_with("Snapshots for ") && line.ends_with(':')
}

/// `YYYY-MM-DDTHH:MM:SS` of a well-formed snapshot name with a real calendar time, else `None`.
fn snapshot_date(name: &str) -> Option<String> {
    let stamp = name
        .strip_prefix("com.apple.TimeMachine.")?
        .strip_suffix(".local")?;
    let mut parts = stamp.split('-');
    let year = digits(parts.next()?, 4)?;
    let month = digits(parts.next()?, 2)?;
    let day = digits(parts.next()?, 2)?;
    let time = digits(parts.next()?, 6)?;
    if parts.next().is_some() {
        return None;
    }
    let (hour, minute, second) = (time / 10_000, time / 100 % 100, time % 100);
    let valid =
        (1..=days_in_month(year, month)).contains(&day) && hour < 24 && minute < 60 && second < 60;
    valid.then(|| format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"))
}

/// `text` as a number when it is exactly `len` ASCII digits (no sign, no spaces).
fn digits(text: &str, len: usize) -> Option<u32> {
    if text.len() == len && text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// Days in `month` (1..=12) of `year` in the Gregorian calendar; `0` for an invalid month.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

/// Why the snapshot list is unknown.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotsError {
    /// `tmutil` is not installed or not executable.
    #[error("tmutil not found")]
    ToolMissing,
    /// `tmutil` exited with a non-zero status.
    #[error("tmutil exited with status {code}")]
    NonZeroExit {
        /// The exit status.
        code: i32,
    },
    /// `tmutil` did not answer within [`TMUTIL_TIMEOUT`].
    #[error("tmutil timed out")]
    TimedOut,
    /// `tmutil` could not be run for another reason.
    #[error("tmutil could not be run: {reason}")]
    SpawnFailed {
        /// Human-readable cause.
        reason: String,
    },
}

impl SnapshotsError {
    /// Stable machine code for `snapshots_error`: `tool_missing`, `nonzero_exit`, `timeout`,
    /// `spawn_failed`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ToolMissing => "tool_missing",
            Self::NonZeroExit { .. } => "nonzero_exit",
            Self::TimedOut => "timeout",
            Self::SpawnFailed { .. } => "spawn_failed",
        }
    }
}

/// Run `TMUTIL_PROGRAM TMUTIL_ARGS` once through `runner` with `TMUTIL_TIMEOUT` and parse the
/// result. Zero snapshots is `Ok` with an empty list, not an error.
///
/// Effects: exactly one read-only command (`tmutil listlocalsnapshots /`), as an argument array,
/// never through a shell, never with `sudo`, never a mutating verb (INV-10).
///
/// # Errors
/// [`SnapshotsError`] when the tool is missing, times out, cannot be run, or exits non-zero; the
/// caller must then report the list as **unknown** (never as empty).
pub fn list_local_snapshots(runner: &dyn CommandRunner) -> Result<ParsedSnapshots, SnapshotsError> {
    let output = runner
        .run(TMUTIL_PROGRAM, &TMUTIL_ARGS, TMUTIL_TIMEOUT)
        .map_err(|e| match e {
            CommandError::NotFound => SnapshotsError::ToolMissing,
            CommandError::TimedOut => SnapshotsError::TimedOut,
            CommandError::Failed { reason } => SnapshotsError::SpawnFailed { reason },
        })?;
    if output.exit_code != 0 {
        return Err(SnapshotsError::NonZeroExit {
            code: output.exit_code,
        });
    }
    Ok(parse_listlocalsnapshots(&String::from_utf8_lossy(
        &output.stdout,
    )))
}
