//! Command-line front end and composition root for the cleaner.
//!
//! This is the only place that reads the process environment (`CLEANER_TEST_MODE`, `HOME`,
//! `TMPDIR`). The INV-15 test-mode guard runs first, before any argument is parsed, so even
//! `--version` is refused when it fails: nothing is created and nothing is scanned.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser as _;
use cleaner_cli::args::{Cli, Command};
use cleaner_cli::scan_cmd::{self, ScanEnv};
use cleaner_cli::seams::{SEAM_VARS, TMUTIL_VAR, VOLUME_VAR};
use cleaner_core::testmode;

/// Exit code for a safety refusal (safety-invariants.md).
const EXIT_SAFETY_REFUSAL: u8 = 3;

/// INV-15: with the guard on, canonical `$HOME` must be strictly inside the canonical system temp
/// dir. Anything that cannot be established (HOME unset, a path that does not canonicalize) is
/// refused too (fail closed). `Ok` says whether test mode is on; `Err` carries the message for
/// stderr.
fn guard_test_mode() -> Result<bool, String> {
    let mode = env::var_os("CLEANER_TEST_MODE");
    let enabled = testmode::is_enabled(mode.as_deref());
    if !enabled {
        return Ok(false);
    }
    let raw_home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("refusing to run in test mode: HOME is not set")?;
    let home = raw_home.canonicalize().map_err(|e| {
        format!(
            "refusing to run in test mode: HOME ({}) cannot be resolved: {e}",
            raw_home.display()
        )
    })?;
    let raw_temp = env::temp_dir();
    let temp_dir = raw_temp.canonicalize().map_err(|e| {
        format!(
            "refusing to run in test mode: the system temp dir ({}) cannot be resolved: {e}",
            raw_temp.display()
        )
    })?;
    testmode::check(enabled, &home, &temp_dir).map_err(|v| v.to_string())?;
    Ok(true)
}

/// The test seams are honored only when the INV-15 guard is on (`guard_test_mode` already
/// verified `HOME`). With the guard off, a set seam variable is **refused** rather than ignored:
/// a stray variable must never silently replace `tmutil` or fake a volume (INV-13).
fn refuse_seams_outside_test_mode(test_mode: bool) -> Result<(), String> {
    if test_mode {
        return Ok(());
    }
    match SEAM_VARS.iter().find(|var| env::var_os(var).is_some()) {
        Some(var) => Err(format!(
            "refusing to run: {var} is a test seam and CLEANER_TEST_MODE is not enabled"
        )),
        None => Ok(()),
    }
}

fn main() -> ExitCode {
    if let Err(message) = guard_test_mode().and_then(refuse_seams_outside_test_mode) {
        eprintln!("cleaner: {message}");
        return ExitCode::from(EXIT_SAFETY_REFUSAL);
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => {
            let Some(home) = env::var_os("HOME").map(PathBuf::from) else {
                eprintln!("cleaner: HOME is not set");
                return ExitCode::FAILURE;
            };
            let env = ScanEnv {
                home,
                term_program: env::var("TERM_PROGRAM").ok(),
                argv: env::args_os()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect(),
                tmutil_override: env::var_os(TMUTIL_VAR).map(PathBuf::from),
                volume_override: env::var_os(VOLUME_VAR).map(|v| v.to_string_lossy().into_owned()),
            };
            ExitCode::from(scan_cmd::run(&args, env))
        }
    }
}
