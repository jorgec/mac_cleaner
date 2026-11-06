//! INV-15 test-mode decision (spec 001 AC-001-15). Pure: the composition root reads the
//! environment and canonicalizes paths, then asks this function.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

/// `CLEANER_TEST_MODE=1` was set but `HOME` is not strictly inside the system temp directory.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "refusing to run in test mode: HOME ({}) is not strictly inside the system temp dir ({})",
    .home.display(),
    .temp_dir.display()
)]
pub struct TestModeViolation {
    /// The offending home path, as given.
    pub home: PathBuf,
    /// The temp directory it had to be inside.
    pub temp_dir: PathBuf,
}

/// Interpret the raw `CLEANER_TEST_MODE` value (fail-closed, AC-001-15 amendment): the guard is
/// OFF only when the variable is unset, empty, or exactly `0`; every other value (`1`, `true`,
/// `yes`, `foo`, `00`, ` 0`, non-UTF-8 bytes) turns it ON. Pure.
#[must_use]
pub fn is_enabled(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != OsStr::new("0"))
}

/// Refuse a real home in test mode. With `test_mode == false` there is no restriction. With
/// `test_mode == true`, both paths must be absolute and `home` free of `.`/`..` components, and strictly below
/// `temp_dir` (component-wise; `home == temp_dir` is a violation).
///
/// # Errors
/// [`TestModeViolation`] naming `home`.
pub fn check(test_mode: bool, home: &Path, temp_dir: &Path) -> Result<(), TestModeViolation> {
    // `Path::components` silently drops interior `.`, so look at the raw separators-delimited text.
    let has_dot_segment = home
        .as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .any(|segment| segment == b"." || segment == b"..");
    let strictly_inside = home.starts_with(temp_dir) && home != temp_dir;
    if test_mode
        && !(home.is_absolute() && temp_dir.is_absolute() && !has_dot_segment && strictly_inside)
    {
        return Err(TestModeViolation {
            home: home.to_path_buf(),
            temp_dir: temp_dir.to_path_buf(),
        });
    }
    Ok(())
}
