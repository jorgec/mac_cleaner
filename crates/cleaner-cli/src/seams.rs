//! Hermetic test seams (spec 002b section 3.1). They replace the two process-external adapters
//! (`tmutil`, the Foundation volume query) so the binary can be tested without touching the real
//! machine. The composition root honors them **only** when the INV-15 test-mode guard is on and
//! refuses to start when one is set while it is off ([`SEAM_VARS`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use cleaner_core::ports::{
    CommandError, CommandOutput, CommandRunner, VolumeCapacity, VolumeCaps, VolumeError,
};
use cleaner_core::snapshots::TMUTIL_PROGRAM;

/// Environment variable naming the program run instead of `/usr/bin/tmutil`.
pub const TMUTIL_VAR: &str = "CLEANER_TMUTIL";
/// Environment variable replacing the volume query: `fail` or `<total>:<available>:<important>`.
pub const VOLUME_VAR: &str = "CLEANER_TEST_VOLUME";
/// Every seam variable; each is refused (exit 3) when set outside test mode.
pub const SEAM_VARS: [&str; 2] = [TMUTIL_VAR, VOLUME_VAR];

/// A malformed `CLEANER_TEST_VOLUME` value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{VOLUME_VAR} must be `fail` or `<total>:<available>:<important>` in decimal bytes, got {value:?}"
)]
pub struct VolumeSeamError {
    /// The rejected value.
    pub value: String,
}

/// The replacement volume: a failing query or fixed numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeSeam {
    /// Every query fails with `VolumeError::QueryFailed`.
    Fail,
    /// Every query succeeds with these capacities (bytes).
    Fixed {
        /// `volumeTotalCapacity`.
        total: u64,
        /// `volumeAvailableCapacity`.
        available: u64,
        /// `volumeAvailableCapacityForImportantUsage`.
        important: u64,
    },
}

impl VolumeSeam {
    /// Parse a `CLEANER_TEST_VOLUME` value.
    ///
    /// # Errors
    /// [`VolumeSeamError`] unless the value is `fail` or three decimal `u64`s joined by `:`.
    pub fn parse(value: &str) -> Result<Self, VolumeSeamError> {
        let bad = || VolumeSeamError {
            value: value.to_owned(),
        };
        if value == "fail" {
            return Ok(Self::Fail);
        }
        let numbers: Vec<u64> = value
            .split(':')
            .map(|n| n.parse().map_err(|_| bad()))
            .collect::<Result<_, _>>()?;
        match numbers.as_slice() {
            [total, available, important] => Ok(Self::Fixed {
                total: *total,
                available: *available,
                important: *important,
            }),
            _ => Err(bad()),
        }
    }
}

impl VolumeCapacity for VolumeSeam {
    fn query(&self, _path: &Path) -> Result<VolumeCaps, VolumeError> {
        match *self {
            Self::Fail => Err(VolumeError::QueryFailed {
                reason: format!("{VOLUME_VAR}=fail"),
            }),
            Self::Fixed {
                total,
                available,
                important,
            } => Ok(VolumeCaps {
                mount_point: PathBuf::from("/System/Volumes/Data"),
                total,
                available,
                available_important: important,
                available_opportunistic: important,
            }),
        }
    }
}

/// Runs `inner`, but replaces the program `/usr/bin/tmutil` by `tmutil` (arguments unchanged).
#[derive(Debug)]
pub struct TmutilOverride<R> {
    /// The real runner that executes the replacement.
    pub inner: R,
    /// The program to run instead of `/usr/bin/tmutil`.
    pub tmutil: PathBuf,
}

impl<R: CommandRunner> CommandRunner for TmutilOverride<R> {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError> {
        if program == TMUTIL_PROGRAM {
            match self.tmutil.to_str() {
                Some(replacement) => self.inner.run(replacement, args, timeout),
                None => Err(CommandError::Failed {
                    reason: format!("{TMUTIL_VAR} is not valid UTF-8"),
                }),
            }
        } else {
            self.inner.run(program, args, timeout)
        }
    }
}
