//! CLI wiring of the INV-15 test-mode guard (spec 001 AC-001-15). The decision table itself is
//! tested once in `cleaner-core/tests/safety_testmode.rs`; here we only test what the composition
//! root adds: reading `CLEANER_TEST_MODE`/`HOME`, canonicalizing against the system temp dir
//! (`TMPDIR`), exit code 3, a message naming HOME, and "nothing created".
//!
//! The real home is never used: every `HOME` and `TMPDIR` handed to the child is a directory under a
//! `tempfile::TempDir`. A HOME that is "outside the system temp dir" is produced by pointing the
//! child's `TMPDIR` at a *different* temp subdirectory.
//!
//! # Worksheet - composition root, test-mode guard
//! ```text
//! Function:        `cleaner` binary startup (before argument parsing)
//! Contract:        guard ON for any CLEANER_TEST_MODE value except unset / "" / "0" (fail-closed,
//!                  amended AC-001-15); ON and canonical(HOME) not strictly inside canonical(temp_dir)
//!                  -> exit 3, stderr names HOME, stdout empty, nothing created under HOME (no log
//!                  dir). OFF (unset, "", "0") -> no restriction. ON with HOME inside temp ->
//!                  proceeds. (AC-001-15, INV-15)
//! Equivalence classes: ON ("1", "true") & HOME outside | ON & HOME inside | OFF (unset, "0", "")
//! Boundaries:      "1" vs "true" (both refuse: proves the binary calls `is_enabled`, not `== "1"`)
//! Must-never:      creating a log file or any entry under a refused HOME; scanning
//! Selected tests:  ac_001_15_refused_home_exits_3_names_home_and_creates_nothing,
//!                  ac_001_15_guard_is_off_only_for_unset_empty_or_zero_and_allows_home_inside_temp
//!                  (the full value table is the core `is_enabled` test; here only wiring)
//! Deliberately not tested: HOME unset or non-existent in test mode (unspecified, see matrix).
//! ```

use assert_cmd::Command;
use predicates::prelude::*;

/// Directories for one scenario: `fake_tmp` is what the child believes is the system temp dir;
/// `home_inside` is below it; `home_outside` is a sibling of it (so outside it).
struct Dirs {
    _base: tempfile::TempDir,
    fake_tmp: std::path::PathBuf,
    home_inside: std::path::PathBuf,
    home_outside: std::path::PathBuf,
}

/// Build the three directories under a fresh temp dir.
fn dirs() -> Dirs {
    let base = tempfile::tempdir().expect("temp dir");
    let fake_tmp = base.path().join("fake-tmp");
    let home_inside = fake_tmp.join("home-inside");
    let home_outside = base.path().join("home-outside");
    std::fs::create_dir_all(&home_inside).expect("mkdir inside");
    std::fs::create_dir_all(&home_outside).expect("mkdir outside");
    Dirs {
        _base: base,
        fake_tmp,
        home_inside,
        home_outside,
    }
}

/// `cleaner --version` with a fully controlled environment (no inherited HOME/TMPDIR/test mode).
fn cleaner(mode: Option<&str>, home: &std::path::Path, tmp: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("cleaner").expect("binary built");
    cmd.arg("--version")
        .env("HOME", home)
        .env("TMPDIR", tmp)
        .env_remove("CLEANER_TEST_MODE");
    if let Some(m) = mode {
        cmd.env("CLEANER_TEST_MODE", m);
    }
    cmd
}

/// # Design promise
/// AC-001-15 / INV-15: with the guard ON (`CLEANER_TEST_MODE` = `1`, or any other non-off value such
/// as `true`) and a HOME outside the system temp dir, the CLI refuses before doing anything: exit 3,
/// a message naming the offending HOME, no normal output, and nothing created under that HOME (no
/// log dir/file, no scan).
///
/// # Scenario (Given)
/// Child env: `CLEANER_TEST_MODE` in {`1`, `true`}, `TMPDIR=<base>/fake-tmp`,
/// `HOME=<base>/home-outside` (an empty directory that is a sibling, not a descendant, of the temp
/// dir).
///
/// # Action (When)
/// Run `cleaner --version` for each mode value.
///
/// # Expected (Then)
/// Exit code 3; stderr contains `home-outside`; stdout is empty; `home-outside` still has no entries.
///
/// # Must never
/// Create `Library/Logs/mac-cleaner` (or anything) under the refused HOME; print normal output.
///
/// # Would catch
/// Opening the audit log before checking the guard; exit code 1/2 instead of 3; a generic message
/// without the path; checking only after argument parsing.
///
/// # Why this test (not redundant)
/// Only wiring test of the refusal path (the `true` row proves the fail-closed env policy is wired in,
/// not an exact `== "1"` comparison); the decision rules are in the core tests.
#[test]
fn ac_001_15_refused_home_exits_3_names_home_and_creates_nothing() {
    // Arrange
    let d = dirs();

    for mode in ["1", "true"] {
        // Act
        let assert = cleaner(Some(mode), &d.home_outside, &d.fake_tmp).assert();

        // Assert
        assert
            .code(3)
            .stderr(predicate::str::contains("home-outside"))
            .stdout(predicate::str::is_empty());
        let leftovers = std::fs::read_dir(&d.home_outside)
            .expect("read refused home")
            .count();
        assert_eq!(
            leftovers, 0,
            "mode `{mode}`: INV-15: nothing may be created under a refused HOME"
        );
    }
}

/// # Design promise
/// AC-001-15 (fail-closed amendment): the guard is OFF only for unset, empty or `0` (an outside HOME
/// is then fine), and with the guard ON a HOME inside the temp dir is accepted.
///
/// # Scenario (Given)
/// Rows: (`1`, HOME inside temp), (unset, outside), (`0`, outside), (empty, outside).
///
/// # Action (When)
/// Run `cleaner --version` for each.
///
/// # Expected (Then)
/// Every run succeeds (exit 0).
///
/// # Must never
/// Refuse when the guard is off or satisfied (would break every legitimate run and CI scratch HOME).
///
/// # Would catch
/// Treating `0` or empty as "on" (the spec's off values), or refusing a HOME that is inside the temp
/// dir because of an un-canonicalized `/var` vs `/private/var` comparison.
///
/// # Why this test (not redundant)
/// The off-values and the accept path exist only in the composition root; the refusal side (including
/// `true`) is in the previous test and the full value table in the core `is_enabled` test.
#[test]
fn ac_001_15_guard_is_off_only_for_unset_empty_or_zero_and_allows_home_inside_temp() {
    // Arrange
    let d = dirs();
    let rows = [
        ("mode-1-home-inside", Some("1"), &d.home_inside),
        ("unset", None, &d.home_outside),
        ("zero", Some("0"), &d.home_outside),
        ("empty", Some(""), &d.home_outside),
    ];

    for (name, mode, home) in rows {
        // Act
        let out = cleaner(mode, home, &d.fake_tmp)
            .output()
            .expect("run cleaner");

        // Assert
        assert_eq!(
            out.status.code(),
            Some(0),
            "row `{name}`: guard must not refuse; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
