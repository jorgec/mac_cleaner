//! `cleaner scan` through the built binary (spec 002 AC-002-2, -3, -7, -13, -14, -16, -17, -18, -19,
//! -21; INV-01, INV-09, INV-13, INV-15). The scan logic, the exit-code policy and the report model are
//! tested in `cleaner-core`; the renderer, selectors, run ids and hint in their own files. **These
//! tests only prove the pieces are wired together** through the real process boundary: argument ->
//! selection -> adapters -> report -> stdout/stderr -> exit code, and the audit file on disk.
//!
//! Hermeticity (INV-15): every scenario runs with `HOME` and `TMPDIR` inside a fresh temp dir and
//! `CLEANER_TEST_MODE=1`; the real `tmutil` is never run (`CLEANER_TMUTIL` points at a canned script)
//! and, except in the one test that checks the real volume adapter, the volume is a fixed fake
//! (`CLEANER_TEST_VOLUME`). Those two seams are honored only in test mode and refused otherwise
//! (`safety_ac_002_19_test_seams_are_refused_outside_test_mode`). See `common/mod.rs`.
//!
//! # Worksheet - `cleaner scan` (composition root)
//! ```text
//! Function:        the `cleaner` binary, subcommand `scan [--rule ID]... [--tier T] [--top N] [--json]`
//! Contract:        guard FIRST (AC-002-19: bad HOME in test mode -> exit 3 before parsing/creating
//!                  anything); invalid selectors -> exit 2, valid values listed, nothing created
//!                  (AC-002-14); run = ULID id, audit log `$HOME/Library/Logs/mac-cleaner/audit-*.jsonl`
//!                  with run_start..run_end and gap-free seq, never pruned by a scan (writes: audit log
//!                  only, INV-01); `--json`: stdout is exactly one JSON document of schema `scan/1`,
//!                  warnings on stderr; human mode: stdout report without ANSI, warnings on stderr;
//!                  exit code = `ScanReport::exit_code` (0 / 4 / 130), 2 usage, 3 refusal; a failed
//!                  volume query or `tmutil` is `null` + error code + exit 4, never 0 (AC-002-2, -21); an
//!                  unavailable audit log warns on stderr, exit 4, the scan still runs (AC-002-17);
//!                  SIGINT -> cancel token -> exit 130 and `run_end.interrupted` (AC-002-18);
//!                  permission-denied entries -> exit 4 and ONE Full Disk Access hint naming the
//!                  terminal app (AC-002-7).
//! Equivalence classes: refused HOME | seam outside test mode | bad selectors | good selectors |
//!                  `--top` | JSON + real volume | human + fixed volume | volume failure | tmutil
//!                  outcomes (ok, non-zero, missing) | permission denied | audit unavailable | SIGINT
//! Boundaries:      guard before arg validation; `--top` default 5 vs 2 vs 0; test mode on vs off
//! Must-never:      create anything under a refused HOME or on invalid usage; run the real tmutil;
//!                  modify the scanned tree; delete an old audit file; print JSON plus anything else on
//!                  stdout; print 0 for unknown; retry/escalate on permission denial
//! Selected tests:  see the fns below (13 tests; the policy table of exit codes is core-tested)
//! Deliberately not tested: `tmutil` timing out (adapter test kills the child; core maps the kind),
//!                  mid-walk SIGINT (core tests cancellation at listing granularity; here the
//!                  deterministic pre-walk window is used), colored output on a TTY (no pty here; the
//!                  spec only forbids ANSI off-TTY), `--help` text, clap's own parsing.
//! ```

mod common;

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use cleaner_cli::render::format_bytes;
use cleaner_core::audit::Record;
use cleaner_core::rules::builtin;
use common::{
    FIXED_PURGEABLE, Sandbox, allocated, bypasses_permissions, json_rule, json_rule_ids, lock_dir,
    parse_json,
};

/// Ids of the built-in rule table, in table order.
fn builtin_ids() -> Vec<String> {
    builtin().into_iter().map(|r| r.id).collect()
}

/// Bytes of a captured stream as text.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The first line of `out` whose first whitespace-separated token is `first`.
fn line_starting<'a>(out: &'a str, first: &str) -> &'a str {
    out.lines()
        .find(|l| l.split_whitespace().next() == Some(first))
        .unwrap_or_else(|| panic!("no line starts with `{first}` in:\n{out}"))
}

/// Number of entries directly inside `dir`.
fn entry_count(dir: &Path) -> usize {
    fs::read_dir(dir).expect("read_dir").count()
}

/// # Design promise
/// AC-002-19 / INV-15: `scan` honors the test-mode guard before doing anything else - before argument
/// validation, before opening the audit log, before scanning: with the guard on and `HOME` outside the
/// system temp dir the process exits 3, names the HOME, prints nothing on stdout and creates nothing.
///
/// # Scenario (Given)
/// `CLEANER_TEST_MODE=1`, `TMPDIR=<base>/tmp`, `HOME=<base>/home-outside` (an empty sibling directory).
/// Four command lines: `scan`, `scan --json`, `scan --rule no-such-rule` (would be exit 2 on its own)
/// and `scan --tier bogus` (clap would reject it).
///
/// # Action (When)
/// Run the binary for each.
///
/// # Expected (Then)
/// Exit code 3 for all four (the guard wins over usage errors), stderr contains `home-outside`, stdout
/// is empty, and `home-outside` still has no entries (no `Library/Logs/mac-cleaner`).
///
/// # Must never
/// Scan, create the log directory, or report a usage error before the safety refusal.
///
/// # Would catch
/// Parsing arguments (clap) before the guard, opening the audit sink first, a guard that only protects
/// `--version`, exit code 2 or 1 for the refusal.
///
/// # Why this test (not redundant)
/// `test_mode.rs` proves the guard for `--version`; this proves the *scan* path (and arg validation)
/// sit behind it.
#[test]
fn safety_ac_002_19_scan_obeys_the_test_mode_guard_before_anything_else() {
    // Arrange
    let sandbox = Sandbox::new();
    let outside = sandbox.outside_home();
    let lines: [&[&str]; 4] = [
        &["scan"],
        &["scan", "--json"],
        &["scan", "--rule", "no-such-rule"],
        &["scan", "--tier", "bogus"],
    ];

    for args in lines {
        // Act
        let out = sandbox
            .cleaner()
            .env("HOME", &outside)
            .args(args)
            .output()
            .expect("run cleaner");

        // Assert
        assert_eq!(
            out.status.code(),
            Some(3),
            "{args:?}: INV-15 refusal must win over everything else; stderr: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains("home-outside"),
            "{args:?}: the refusal must name the HOME, got {:?}",
            text(&out.stderr)
        );
        assert!(
            out.stdout.is_empty(),
            "{args:?}: no normal output on a refusal"
        );
        assert_eq!(
            entry_count(&outside),
            0,
            "{args:?}: INV-15: nothing may be created under a refused HOME"
        );
    }
}

/// # Design promise
/// INV-15 / AC-002-19: the hermetic test seams (`CLEANER_TMUTIL` replaces the `tmutil` program,
/// `CLEANER_TEST_VOLUME` fakes the volume) are honored **only** in test mode. With test mode off, a
/// set seam variable is refused (exit 3, names the variable, nothing created) instead of silently
/// changing which program the tool runs or what it reports - and it is never run.
///
/// # Scenario (Given)
/// `HOME` inside the temp dir (so the guard itself is satisfied), `CLEANER_TEST_MODE` unset or `0`, and
/// exactly one seam variable set per run: `CLEANER_TMUTIL` (pointing at a script that would create a
/// marker file if executed) or `CLEANER_TEST_VOLUME=fail`.
///
/// # Action (When)
/// `cleaner scan`.
///
/// # Expected (Then)
/// Exit 3; stderr names the variable; stdout empty; `HOME` still empty (no log directory); the marker
/// file does not exist (the override program was not run).
///
/// # Must never
/// Execute the override program, report the faked volume, or run the real `tmutil`/volume query behind
/// the seam's back (the refusal happens before any of it).
///
/// # Would catch
/// Reading the seam variables unconditionally (a stray `CLEANER_TMUTIL` in a user's shell would then
/// replace `/usr/bin/tmutil`: a way to run arbitrary code or to fake results), checking test mode
/// after the adapters are built, honoring the seam when the mode value is `0`.
///
/// # Why this test (not redundant)
/// The only test of the seam guard; every other CLI test depends on the seams being honored in test
/// mode, which proves the other direction.
#[test]
fn safety_ac_002_19_test_seams_are_refused_outside_test_mode() {
    // Arrange
    let sandbox = Sandbox::new();
    let marker = sandbox.bin.join("tmutil-was-run");
    sandbox.tmutil(&format!("touch '{}'", marker.display()));
    let modes = [None, Some("0")];
    let seams = ["CLEANER_TMUTIL", "CLEANER_TEST_VOLUME"];

    for mode in modes {
        for seam in seams {
            let mut cmd = sandbox.cleaner();
            cmd.env_remove("CLEANER_TMUTIL")
                .env_remove("CLEANER_TEST_VOLUME")
                .env_remove("CLEANER_TEST_MODE");
            if let Some(m) = mode {
                cmd.env("CLEANER_TEST_MODE", m);
            }
            let value = if seam == "CLEANER_TMUTIL" {
                sandbox.bin.join("tmutil").into_os_string()
            } else {
                "fail".into()
            };
            cmd.env(seam, value);

            // Act
            let out = cmd.arg("scan").output().expect("run cleaner");

            // Assert
            assert_eq!(
                out.status.code(),
                Some(3),
                "mode {mode:?}, {seam}: a test seam outside test mode must be refused; stderr: {}",
                text(&out.stderr)
            );
            assert!(
                text(&out.stderr).contains(seam),
                "mode {mode:?}, {seam}: the refusal must name the variable, got {:?}",
                text(&out.stderr)
            );
            assert!(out.stdout.is_empty(), "mode {mode:?}, {seam}: no report");
            assert_eq!(
                entry_count(&sandbox.home),
                0,
                "mode {mode:?}, {seam}: nothing may be created"
            );
            assert!(
                !marker.exists(),
                "mode {mode:?}, {seam}: the override program must never be executed outside test mode"
            );
        }
    }
}

/// # Design promise
/// AC-002-14: an unknown rule id, an unknown tier or a selector combination that matches nothing is a
/// usage error: exit 2, a message that lists the valid values, nothing scanned, **no audit log or any
/// other file created**.
///
/// # Scenario (Given)
/// An empty `HOME` in test mode. Rows: `--rule nope`; `--rule USER-CACHES` (wrong case);
/// `--tier bogus`; `--rule user-caches --tier caution` (valid but disjoint).
///
/// # Action (When)
/// `cleaner scan <args>`.
///
/// # Expected (Then)
/// Exit 2; stdout empty; stderr contains the offending value and the valid values (all 12 rule ids for
/// the id rows; `safe`, `caution`, `report-only` for the tier row; a non-empty explanation for the
/// disjoint row); `HOME` still has no entries.
///
/// # Must never
/// Treat a typo as "scan nothing, all fine" (exit 0), create `Library/Logs/mac-cleaner`, or scan.
///
/// # Would catch
/// Validating selectors after opening the audit log, silently ignoring unknown ids, an error that does
/// not list the valid values, exit 1 instead of 2.
///
/// # Why this test (not redundant)
/// `select.rs` tests the selection logic; this is the only test of the exit code, the listing of valid
/// tiers (clap) and "no log created".
#[test]
fn ac_002_14_invalid_selectors_exit_2_list_valid_values_and_create_nothing() {
    // Arrange
    let sandbox = Sandbox::new();
    let ids = builtin_ids();
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut with_ids = vec!["nope"];
    with_ids.extend(&id_refs);
    let mut with_case = vec!["USER-CACHES"];
    with_case.extend(&id_refs);
    let rows: Vec<(Vec<&str>, Vec<&str>)> = vec![
        (vec!["scan", "--rule", "nope"], with_ids),
        (vec!["scan", "--rule", "USER-CACHES"], with_case),
        (
            vec!["scan", "--tier", "bogus"],
            vec!["bogus", "safe", "caution", "report-only"],
        ),
        (
            vec!["scan", "--rule", "user-caches", "--tier", "caution"],
            vec![],
        ),
    ];

    for (args, must_mention) in rows {
        // Act
        let out = sandbox.cleaner().args(&args).output().expect("run cleaner");

        // Assert
        let stderr = text(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: usage errors exit 2; stderr: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "{args:?}: nothing on stdout for a usage error"
        );
        assert!(
            !stderr.trim().is_empty(),
            "{args:?}: the user must be told what is wrong"
        );
        for token in must_mention {
            assert!(
                stderr.contains(token),
                "{args:?}: the message must mention `{token}` (offending value and valid choices): {stderr}"
            );
        }
        assert_eq!(
            entry_count(&sandbox.home),
            0,
            "{args:?}: a usage error must create nothing (no audit log)"
        );
    }
}

/// # Design promise
/// AC-002-14 / INV-02: with no selectors `scan` examines every rule (allowed because it is read-only),
/// `--rule` (repeatable) and `--tier` narrow it, rules are always processed in table order whatever the
/// flag order, and the output never marks anything selected or recommended.
///
/// # Scenario (Given)
/// An empty `HOME` in test mode (every root absent: exit 0). Rows: no selectors; `--rule trash --rule
/// user-caches --rule trash`; `--tier report-only`.
///
/// # Action (When)
/// `cleaner scan --json <selectors>`.
///
/// # Expected (Then)
/// Exit 0; `rules[].id` is: all 12 ids in table order; `[user-caches, trash]`; `[ios-backups]`. The JSON
/// text contains neither `recommend` nor `select`.
///
/// # Must never
/// Scan a rule that was not asked for; reorder rules by flag order (hardlink attribution depends on
/// table order); emit a "selected"/"recommended" marker.
///
/// # Would catch
/// Selectors parsed but not applied, `Vec<String>` order leaking into rule order, an `is_selected`
/// field creeping into the report.
///
/// # Why this test (not redundant)
/// Proves the selection result reaches the scan (the logic itself is `select.rs`); the other CLI tests
/// all scan the full table.
#[test]
fn ac_002_14_selectors_limit_the_scan_and_no_selectors_scans_all_without_selecting() {
    // Arrange
    let sandbox = Sandbox::new();
    let rows: Vec<(Vec<&str>, Vec<String>)> = vec![
        (vec![], builtin_ids()),
        (
            vec![
                "--rule",
                "trash",
                "--rule",
                "user-caches",
                "--rule",
                "trash",
            ],
            vec!["user-caches".to_owned(), "trash".to_owned()],
        ),
        (
            vec!["--tier", "report-only"],
            vec!["ios-backups".to_owned()],
        ),
    ];

    for (selectors, want) in rows {
        // Act
        let out = sandbox
            .cleaner()
            .args(["scan", "--json"])
            .args(&selectors)
            .output()
            .expect("run cleaner");

        // Assert
        assert_eq!(
            out.status.code(),
            Some(0),
            "{selectors:?}: absent roots are not a problem; stderr: {}",
            text(&out.stderr)
        );
        let report = parse_json(&out.stdout);
        assert_eq!(
            json_rule_ids(&report),
            want,
            "{selectors:?}: scanned rules, in table order"
        );
        let raw = text(&out.stdout).to_lowercase();
        assert!(
            !raw.contains("recommend") && !raw.contains("select"),
            "{selectors:?}: INV-02 nothing may be marked selected or recommended"
        );
    }
}

/// # Design promise
/// AC-002-13: `--top N` limits the per-rule list of largest children (default 5; 0 lists none), largest
/// first, with the child's allocated bytes.
///
/// # Scenario (Given)
/// `Library/Caches` with seven files `f1..f7` of 8 KiB x k bytes (distinct allocations).
///
/// # Action (When)
/// `cleaner scan --json --rule user-caches` with no `--top`, `--top 2`, `--top 0`.
///
/// # Expected (Then)
/// `top` has 5, 2 and 0 entries; the entries are `f7, f6, ...` (descending) with `bytes` equal to the
/// file's allocated size (`st_blocks * 512`, measured independently).
///
/// # Must never
/// Ignore the flag, list more than asked, or list smaller children before larger ones.
///
/// # Would catch
/// A hard-coded 5, `--top` parsed but not passed into `ScanOptions`, an ascending list.
///
/// # Why this test (not redundant)
/// `ac_002_13` in core covers ordering and limits against a fake; this proves the CLI flag and its
/// default are wired.
#[test]
fn ac_002_13_top_flag_and_its_default_limit_the_children_listed() {
    // Arrange
    let sandbox = Sandbox::new();
    let files: Vec<_> = (1..=7)
        .map(|k| sandbox.file(&format!("Library/Caches/f{k}"), k * 8192))
        .collect();
    let rows: [(&[&str], usize); 3] = [(&[], 5), (&["--top", "2"], 2), (&["--top", "0"], 0)];

    for (flags, want_len) in rows {
        // Act
        let out = sandbox
            .cleaner()
            .args(["scan", "--json", "--rule", "user-caches"])
            .args(flags)
            .output()
            .expect("run cleaner");

        // Assert
        let report = parse_json(&out.stdout);
        let top = json_rule(&report, "user-caches")["top"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(top.len(), want_len, "{flags:?}: number of top children");
        for (entry, file) in top.iter().zip(files.iter().rev()) {
            assert_eq!(
                (entry["path"].as_str(), entry["bytes"].as_u64()),
                (file.to_str(), Some(allocated(file))),
                "{flags:?}: entries are the largest files, descending, with allocated bytes"
            );
        }
    }
}

/// # Design promise
/// AC-002-16 / AC-002-3 / AC-002-2 / AC-002-21 / INV-12: with `--json` stdout is **exactly one JSON
/// document** of schema `scan/1` and nothing else, with real numbers from the real adapters: the volume
/// holding `$HOME` (queried through the real Foundation adapter), the snapshots `tmutil` listed (canned),
/// and the allocated bytes of the fixture - including that the tool's own audit log is not reported as
/// reclaimable (spec table: `user-logs` excludes `Library/Logs/mac-cleaner`). A healthy run has an empty
/// stderr and exit 0.
///
/// # Scenario (Given)
/// Test mode, `CLEANER_TEST_VOLUME` removed (real volume query of the temp `HOME`), a canned `tmutil`
/// listing one valid snapshot name and one foreign line. Fixture: `Library/Caches/app/blob` (8 KiB) and
/// `Library/Logs/app.log` (100 bytes).
///
/// # Action (When)
/// `cleaner scan --json`.
///
/// # Expected (Then)
/// Exit 0, stderr empty, stdout parses as one document with: `schema == "scan/1"`; a 26-character
/// `run_id` equal to the audit file's; `home` equal to `$HOME` as given; `volume.total > 0`,
/// `available <= total`, `mount_point` on the same device as `$HOME`, `volume_error == null`, and
/// `purgeable == clamp(important - available, 0, total)` with the matching `purgeable_clamped`;
/// `snapshots` = the valid name with date `2026-11-06T12:34:56` and the foreign line with `date: null`,
/// `snapshots_unparsed == 1`; `user-caches.bytes == allocated(blob)`; `user-logs.bytes ==
/// allocated(app.log)` (the audit file under `Library/Logs/mac-cleaner` is not counted).
///
/// # Must never
/// Print anything but the JSON on stdout; count the audit log as reclaimable; report the volume of a
/// different path; report a failed value as 0.
///
/// # Would catch
/// A banner or warning on stdout, querying `/` instead of `$HOME`, an adapter that is not wired
/// (zeros), forgetting the own-logs exclusion at the composition root (e.g. rules built without the
/// exclude), a `run_id` that differs from the log's.
///
/// # Why this test (not redundant)
/// The only end-to-end check that the real volume adapter, the snapshot plumbing and the JSON
/// contract meet in the binary; the shape itself is pinned in core.
#[test]
fn ac_002_16_json_mode_prints_only_scan_1_json_with_real_volume_snapshots_and_sizes() {
    // Arrange
    let sandbox = Sandbox::new();
    let blob = sandbox.file("Library/Caches/app/blob", 8192);
    let log = sandbox.file("Library/Logs/app.log", 100);
    sandbox.tmutil(
        "printf 'Snapshots for disk /:\\ncom.apple.TimeMachine.2026-11-06-123456.local\\nstrange\\n'",
    );

    // Act
    let out = sandbox
        .cleaner()
        .env_remove("CLEANER_TEST_VOLUME")
        .args(["scan", "--json"])
        .output()
        .expect("run cleaner");

    // Assert
    assert_eq!(
        out.status.code(),
        Some(0),
        "a healthy scan exits 0; stderr: {}",
        text(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "a healthy run has no warnings: {:?}",
        text(&out.stderr)
    );
    let report = parse_json(&out.stdout);
    assert_eq!(report["schema"], "scan/1", "schema id");
    let run_id = report["run_id"].as_str().unwrap_or_default();
    assert_eq!(run_id.len(), 26, "run_id is a ULID: {run_id:?}");
    let files = sandbox.audit_files();
    let records = Sandbox::records(files.first().expect("an audit file was written"));
    assert!(
        records.iter().all(|r| r.run_id == run_id),
        "the report and the audit log must share the run id {run_id}"
    );
    assert_eq!(
        report["home"].as_str(),
        sandbox.home.to_str(),
        "home as given, not canonicalized"
    );

    let volume = &report["volume"];
    let total = volume["total"].as_u64().expect("total is known");
    let available = volume["available"].as_u64().expect("available is known");
    let important = volume["available_important"]
        .as_u64()
        .expect("important is known");
    assert!(
        total > 0 && available <= total,
        "volume sanity: total {total}, available {available}"
    );
    assert!(
        volume["volume_error"].is_null(),
        "no volume error on a healthy machine"
    );
    let mount = volume["mount_point"].as_str().expect("mount point");
    let dev = |p: &Path| {
        use std::os::unix::fs::MetadataExt as _;
        fs::metadata(p).map(|m| m.dev()).expect("stat")
    };
    assert_eq!(
        dev(Path::new(mount)),
        dev(&sandbox.home),
        "AC-002-3: the volume reported must be the one holding $HOME"
    );
    let raw = i128::from(important) - i128::from(available);
    let want_purgeable = raw.clamp(0, i128::from(total));
    assert_eq!(
        i128::from(volume["purgeable"].as_u64().expect("purgeable is known")),
        want_purgeable,
        "purgeable = clamp(important - available, 0, total)"
    );
    assert_eq!(
        volume["purgeable_clamped"].as_bool(),
        Some(raw < 0 || raw > i128::from(total)),
        "purgeable_clamped flags exactly the adjusted cases"
    );

    let snapshots = report["snapshots"].as_array().expect("snapshots listed");
    assert_eq!(snapshots.len(), 2, "both lines are kept: {snapshots:?}");
    assert_eq!(
        snapshots[0]["date"], "2026-11-06T12:34:56",
        "the valid name gets its local date"
    );
    assert!(
        snapshots[1]["date"].is_null(),
        "the foreign line is kept with date null"
    );
    assert_eq!(report["snapshots_unparsed"], 1, "one unparsed line");

    assert_eq!(
        json_rule(&report, "user-caches")["bytes"].as_u64(),
        Some(allocated(&blob)),
        "user-caches counts the allocated bytes of the fixture"
    );
    assert_eq!(
        json_rule(&report, "user-logs")["bytes"].as_u64(),
        Some(allocated(&log)),
        "INV-12: the tool's own audit log under Library/Logs/mac-cleaner must not be counted as reclaimable"
    );
}

/// # Design promise
/// AC-002-16 / AC-002-3: the human report goes to stdout (nothing on stderr for a healthy run), shows
/// the volume and the OS-managed purgeable number from the injected volume, the rule bytes in readable
/// units, and contains no ANSI escape bytes - whether or not `NO_COLOR` is set, since stdout is a pipe,
/// not a TTY.
///
/// # Scenario (Given)
/// Test mode with the fixed volume (494.4 GB total, 365.8 GB available, 4.2 GB purgeable) and one
/// fixture file `Library/Caches/app/blob`. Rows: `NO_COLOR` unset; `NO_COLOR=1`.
///
/// # Action (When)
/// `cleaner scan` (human mode).
///
/// # Expected (Then)
/// Exit 0; stderr empty; stdout has a `Volume` line with `total 494.4 GB`, a `Purgeable` line with
/// `4.2 GB`, a `Safe` line containing `user-caches <formatted allocated bytes>`; no ESC byte in either
/// stream.
///
/// # Must never
/// Print ANSI sequences to a pipe; send the report to stderr; show purgeable summed into a tier.
///
/// # Would catch
/// Unconditional color codes, `println!` of the debug model, the report printed on stderr, the volume
/// seam not reaching the renderer.
///
/// # Why this test (not redundant)
/// `render.rs` pins the report's content for canned data; this is the only test that the binary prints
/// it, on the right stream, from live adapter values, without ANSI off a TTY.
#[test]
fn ac_002_16_human_report_is_printed_on_stdout_from_live_values_without_ansi_off_a_tty() {
    // Arrange
    let sandbox = Sandbox::new();
    let blob = sandbox.file("Library/Caches/app/blob", 8192);

    for no_color in [None, Some("1")] {
        let mut cmd = sandbox.cleaner();
        if let Some(v) = no_color {
            cmd.env("NO_COLOR", v);
        }

        // Act
        let out = cmd.arg("scan").output().expect("run cleaner");

        // Assert
        let stdout = text(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "NO_COLOR={no_color:?}: exit 0; stderr: {}",
            text(&out.stderr)
        );
        assert!(
            out.stderr.is_empty(),
            "NO_COLOR={no_color:?}: no warnings expected"
        );
        assert!(
            line_starting(&stdout, "Volume").contains("total 494.4 GB"),
            "NO_COLOR={no_color:?}: Volume line from the injected volume:\n{stdout}"
        );
        assert!(
            line_starting(&stdout, "Purgeable").contains(&format_bytes(FIXED_PURGEABLE)),
            "NO_COLOR={no_color:?}: Purgeable line:\n{stdout}"
        );
        assert!(
            line_starting(&stdout, "Safe")
                .contains(&format!("user-caches {}", format_bytes(allocated(&blob)))),
            "NO_COLOR={no_color:?}: the Safe tier line must list user-caches with its bytes:\n{stdout}"
        );
        assert!(
            !out.stdout.contains(&0x1b) && !out.stderr.contains(&0x1b),
            "NO_COLOR={no_color:?}: no ANSI escapes when stdout is not a TTY"
        );
    }
}

/// # Design promise
/// AC-002-17 / INV-11 / INV-01: a scan writes exactly one audit run to `$HOME/Library/Logs/mac-cleaner`:
/// `run_start` (argv, selected rule ids, home) first, one `scan_result` per scanned rule in order,
/// `run_end` last, one run id, gap-free `seq` - and prints that file's path and the run id. A scan is
/// read-only: the scanned tree is unchanged and an old audit file is **not** pruned.
///
/// # Scenario (Given)
/// Test mode; fixtures `Library/Caches/app/blob` and `Library/Logs/app.log`; an old
/// `Library/Logs/mac-cleaner/audit-2000-01-01.jsonl` (far past any retention window) with known content.
/// Fingerprint of the tree (kind, mode, size, mtime of every entry outside the log directory) taken
/// before.
///
/// # Action (When)
/// `cleaner scan --rule user-caches --rule user-logs` (human mode).
///
/// # Expected (Then)
/// Exit 0. Exactly two audit files: the old one byte-identical, and today's, whose decoded records are
/// `run_start` (argv ends with the passed arguments, `rule_ids == [user-caches, user-logs]`, `home` ==
/// `$HOME`), `scan_result` x2 in that order, `run_end` (exit 0, not interrupted), `seq == 1..=n`, one
/// `run_id`. Stdout has an `Audit log:` line containing today's file path and `run <run_id>`. The tree
/// fingerprint after equals the one before.
///
/// # Must never
/// Modify or delete anything outside the audit file (INV-01), including pruning the 2000 file; leave a
/// gap in `seq`; print a different path than the file written.
///
/// # Would catch
/// A composition root that skips `run_end`, a second `AuditLog` per phase (seq restarts), calling
/// `prune` at the end of a scan, printing `~`-abbreviated or canonicalized paths, writing
/// `run_start` with the wrong rule list.
///
/// # Why this test (not redundant)
/// The only end-to-end check of the audit file on disk; core tests the record sequence against an
/// in-memory sink and the file adapter has its own tests.
#[test]
#[allow(clippy::too_many_lines, reason = "end-to-end scenario")]
fn ac_002_17_scan_writes_one_gap_free_audit_run_prints_its_path_and_changes_nothing() {
    // Arrange
    let sandbox = Sandbox::new();
    sandbox.file("Library/Caches/app/blob", 8192);
    sandbox.file("Library/Logs/app.log", 100);
    let old = sandbox.log_dir().join("audit-2000-01-01.jsonl");
    fs::create_dir_all(sandbox.log_dir()).expect("mkdir log dir");
    let old_content = "{\"old\":true}\n";
    common::put(&old, old_content);
    let before = sandbox.tree_fingerprint();

    // Act
    let out = sandbox
        .cleaner()
        .args(["scan", "--rule", "user-caches", "--rule", "user-logs"])
        .output()
        .expect("run cleaner");

    // Assert
    assert_eq!(
        out.status.code(),
        Some(0),
        "exit 0; stderr: {}",
        text(&out.stderr)
    );
    let files = sandbox.audit_files();
    assert_eq!(
        files.len(),
        2,
        "the old file and exactly one new run file: {files:?}"
    );
    assert_eq!(
        fs::read_to_string(&old).expect("old audit file still there"),
        old_content,
        "INV-01: a scan must not prune or touch old audit files"
    );
    let today = files
        .iter()
        .find(|f| **f != old)
        .expect("today's audit file");
    let records = Sandbox::records(today);
    let run_id = records
        .first()
        .map(|r| r.run_id.clone())
        .unwrap_or_default();
    for (i, r) in records.iter().enumerate() {
        assert_eq!(
            r.seq,
            i as u64 + 1,
            "record #{i}: seq must be gap-free from 1"
        );
        assert_eq!(
            r.run_id, run_id,
            "record #{i}: one run id for the whole run"
        );
    }
    match records.first().map(|r| &r.record) {
        Some(Record::RunStart {
            argv,
            rule_ids,
            home,
            ..
        }) => {
            assert_eq!(
                argv.iter().skip(1).map(String::as_str).collect::<Vec<_>>(),
                ["scan", "--rule", "user-caches", "--rule", "user-logs"],
                "run_start records the arguments"
            );
            assert_eq!(
                rule_ids,
                &["user-caches", "user-logs"],
                "run_start records the selected rules in order"
            );
            assert_eq!(home, &sandbox.home, "run_start records $HOME as given");
        }
        other => panic!("the first record must be run_start, got {other:?}"),
    }
    let results: Vec<&str> = records
        .iter()
        .filter_map(|r| match &r.record {
            Record::ScanResult { rule_id, .. } => Some(rule_id.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        results,
        ["user-caches", "user-logs"],
        "one scan_result per rule, in order"
    );
    assert!(
        matches!(
            records.last().map(|r| &r.record),
            Some(Record::RunEnd {
                exit_code: 0,
                interrupted: false,
                ..
            })
        ),
        "the last record must be run_end(exit 0, not interrupted), got {:?}",
        records.last()
    );
    let stdout = text(&out.stdout);
    let audit_line = line_starting(&stdout, "Audit");
    assert!(
        audit_line.contains(today.to_str().expect("utf-8"))
            && audit_line.contains(&format!("run {run_id}")),
        "the Audit log line must show the file path and the run id: {audit_line:?}"
    );
    assert_eq!(
        sandbox.tree_fingerprint(),
        before,
        "INV-01: the scanned tree (everything outside the audit log) must be unchanged"
    );
}

/// # Design promise
/// AC-002-2 / INV-13: when the volume query fails the capacity and purgeable numbers are **unknown**
/// (`null` in JSON, the word `unknown` in the human report - never `0`), the failure code is reported,
/// the rule scanning still runs, and the exit code is 4.
///
/// # Scenario (Given)
/// Test mode with `CLEANER_TEST_VOLUME=fail` and one fixture file in `Library/Caches`. Two runs: `--json`
/// and human.
///
/// # Action (When)
/// `cleaner scan [--json]`.
///
/// # Expected (Then)
/// Both exit 4. JSON: `volume.purgeable`, `total`, `available` are `null`, `volume_error ==
/// "query_failed"`, and `user-caches.bytes` is still the fixture's allocated size. Human: the `Purgeable`
/// line contains `unknown` and no digit; the `Safe` line is still printed.
///
/// # Must never
/// Show `0`/`0 B` for the unknown purgeable value; abort the scan because the volume failed.
///
/// # Would catch
/// `unwrap_or(0)` in the composition root, aborting on a volume error, exit 0 with a missing number.
///
/// # Why this test (not redundant)
/// Core proves null-not-zero for the model and `render.rs` for the renderer; this proves the failure
/// travels adapter -> report -> stream -> exit code.
#[test]
fn ac_002_2_a_failed_volume_query_is_unknown_not_zero_exit_4_and_the_scan_continues() {
    // Arrange
    let sandbox = Sandbox::new();
    let blob = sandbox.file("Library/Caches/app/blob", 8192);

    // Act
    let json_out = sandbox
        .cleaner()
        .env("CLEANER_TEST_VOLUME", "fail")
        .args(["scan", "--json"])
        .output()
        .expect("run cleaner");
    let human_out = sandbox
        .cleaner()
        .env("CLEANER_TEST_VOLUME", "fail")
        .arg("scan")
        .output()
        .expect("run cleaner");

    // Assert
    assert_eq!(json_out.status.code(), Some(4), "unknown volume exits 4");
    let report = parse_json(&json_out.stdout);
    let volume = &report["volume"];
    assert!(
        volume["purgeable"].is_null() && volume["total"].is_null() && volume["available"].is_null(),
        "INV-13: unknown values are null, never 0: {volume}"
    );
    assert_eq!(
        volume["volume_error"], "query_failed",
        "the failure code is reported"
    );
    assert_eq!(
        json_rule(&report, "user-caches")["bytes"].as_u64(),
        Some(allocated(&blob)),
        "rule scanning must continue after a volume failure"
    );
    assert_eq!(human_out.status.code(), Some(4), "human mode exits 4 too");
    let stdout = text(&human_out.stdout);
    let purge = line_starting(&stdout, "Purgeable");
    assert!(
        purge.contains("unknown") && !purge.bytes().any(|b| b.is_ascii_digit()),
        "INV-13: the human report must say unknown, not a number: {purge:?}"
    );
    assert!(
        line_starting(&stdout, "Safe").contains("user-caches"),
        "the rule results must still be shown:\n{stdout}"
    );
}

/// # Design promise
/// AC-002-21: the binary asks `tmutil` for `listlocalsnapshots /` as an argument array, shows what it
/// lists, and reports a missing tool or a failing tool as **unknown** snapshots (`null` +
/// `snapshots_error`, exit 4), never as "no snapshots".
///
/// # Scenario (Given)
/// Test mode; the program behind `CLEANER_TMUTIL` is, per row: a script that records its arguments and
/// prints only the header (zero snapshots); a script exiting 7; a path that does not exist.
///
/// # Action (When)
/// `cleaner scan --json --rule trash`.
///
/// # Expected (Then)
/// Row 1: exit 0, `snapshots == []`, `snapshots_error` null, the recorded arguments are exactly
/// `listlocalsnapshots` and `/`. Row 2: exit 4, `snapshots` null, `snapshots_error == "nonzero_exit"`.
/// Row 3: exit 4, `snapshots` null, `snapshots_error == "tool_missing"`. The `rules` array is present
/// in every row.
///
/// # Must never
/// Pass extra or mutating arguments; turn a failure into an empty list; abort the scan.
///
/// # Would catch
/// A runner that joins args into a shell string, ignoring the exit status, `unwrap_or_default()` of the
/// error, a composition root that hard-codes "no snapshots".
///
/// # Why this test (not redundant)
/// The adapter's classes are tested on harmless programs and the mapping in core; this proves the real
/// runner is the one the scan uses and that its failures surface (the timeout row is adapter-tested).
#[test]
fn ac_002_21_tmutil_arguments_and_failures_surface_through_the_binary() {
    // Arrange
    let sandbox = Sandbox::new();
    let args_file = sandbox.bin.join("tmutil-args");

    // Row 1: healthy, records arguments.
    sandbox.tmutil(&format!(
        "printf '%s\\n' \"$@\" > '{}'\nprintf 'Snapshots for disk /:\\n'",
        args_file.display()
    ));
    let ok = sandbox
        .cleaner()
        .args(["scan", "--json", "--rule", "trash"])
        .output()
        .expect("run cleaner");
    // Row 2: tool fails.
    sandbox.tmutil("exit 7");
    let failing = sandbox
        .cleaner()
        .args(["scan", "--json", "--rule", "trash"])
        .output()
        .expect("run cleaner");
    // Row 3: tool missing.
    let missing = sandbox
        .cleaner()
        .env("CLEANER_TMUTIL", "/nonexistent-dir/tmutil")
        .args(["scan", "--json", "--rule", "trash"])
        .output()
        .expect("run cleaner");

    // Assert
    assert_eq!(
        ok.status.code(),
        Some(0),
        "row 1 exit; stderr: {}",
        text(&ok.stderr)
    );
    let report = parse_json(&ok.stdout);
    assert_eq!(
        report["snapshots"],
        serde_json::json!([]),
        "row 1: zero snapshots is []"
    );
    assert!(report["snapshots_error"].is_null(), "row 1: no error");
    assert_eq!(
        fs::read_to_string(&args_file).expect("the fake recorded its arguments"),
        "listlocalsnapshots\n/\n",
        "AC-002-21: exactly `listlocalsnapshots /` as separate arguments"
    );
    for (name, out, code) in [
        ("exit 7", &failing, "nonzero_exit"),
        ("missing", &missing, "tool_missing"),
    ] {
        assert_eq!(
            out.status.code(),
            Some(4),
            "{name}: a failing tmutil makes the scan partial"
        );
        let report = parse_json(&out.stdout);
        assert!(
            report["snapshots"].is_null(),
            "{name}: INV-13 unknown is null, not []"
        );
        assert_eq!(report["snapshots_error"], code, "{name}: error code");
        assert!(
            report["rules"].as_array().is_some_and(|r| r.len() == 1),
            "{name}: the rule scan still ran"
        );
    }
}

/// # Design promise
/// AC-002-7 / INV-09 / INV-10: a directory the OS refuses to list (the typical TCC/permission case) is
/// skipped and logged with its path, the scan continues with everything else, the rule is `partial`,
/// the exit code is 4, and the user gets exactly one Full Disk Access hint naming the *terminal app*
/// (human: on stdout; `--json`: on stderr, stdout stays pure JSON). Nothing is retried or escalated.
///
/// # Scenario (Given)
/// Test mode, `TERM_PROGRAM=iTerm.app`. `Library/Caches/ok/file` (8 KiB, readable) and
/// `Library/Caches/locked/secret` where `locked` is `chmod 000` (restored by a guard afterwards). Two
/// separate sandboxes with that fixture: one run human, one run `--json`. Skipped if the test runs as
/// root (permissions would not deny).
///
/// # Action (When)
/// `cleaner scan --rule user-caches` and `cleaner scan --json --rule user-caches`.
///
/// # Expected (Then)
/// Both exit 4. Human stdout has exactly one line mentioning `Full Disk Access`, naming `iTerm`.
/// JSON stdout parses; `user-caches.status == "partial"`, `bytes == allocated(ok/file)`,
/// `skipped_by_reason.permission_denied == 1`; stderr has exactly one `Full Disk Access` line naming
/// `iTerm`. The audit log holds one `skipped{path == locked dir, reason permission_denied}`.
///
/// # Must never
/// Abort or exit 0; count anything inside `locked`; show the hint per entry or inside the JSON stream;
/// change the permissions of `locked` or try another way in (INV-10).
///
/// # Would catch
/// Treating a listing error as fatal, swallowing it (exit 0, bytes silently too small), a hint printed
/// twice or naming `cleaner`, a hint on stdout in `--json` mode (breaks `jq`).
///
/// # Why this test (not redundant)
/// The only end-to-end test of the real adapter's permission error through the whole binary, of the
/// hint routing and of the exit code 4 for skips.
#[test]
fn safety_ac_002_7_an_unreadable_directory_is_skipped_logged_hinted_once_and_exits_4() {
    // Arrange
    let human_box = Sandbox::new();
    let json_box = Sandbox::new();
    if bypasses_permissions(&human_box.home) {
        eprintln!("skipped: running as root, chmod 000 does not deny access");
        return;
    }
    let ok_file = human_box.file("Library/Caches/ok/file", 8192);
    let locked = human_box.dir("Library/Caches/locked");
    human_box.file("Library/Caches/locked/secret", 8192);
    let ok_json = json_box.file("Library/Caches/ok/file", 8192);
    let locked_json = json_box.dir("Library/Caches/locked");
    json_box.file("Library/Caches/locked/secret", 8192);
    let _g1 = lock_dir(&locked);
    let _g2 = lock_dir(&locked_json);

    // Act
    let human = human_box
        .cleaner()
        .env("TERM_PROGRAM", "iTerm.app")
        .args(["scan", "--rule", "user-caches"])
        .output()
        .expect("run cleaner");
    let json = json_box
        .cleaner()
        .env("TERM_PROGRAM", "iTerm.app")
        .args(["scan", "--json", "--rule", "user-caches"])
        .output()
        .expect("run cleaner");

    // Assert
    assert_eq!(
        human.status.code(),
        Some(4),
        "skips exit 4; stderr: {}",
        text(&human.stderr)
    );
    let stdout = text(&human.stdout);
    let hints: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("Full Disk Access"))
        .collect();
    assert!(
        hints.len() == 1 && hints.iter().all(|l| l.contains("iTerm")),
        "exactly one hint naming the terminal app on stdout, got {hints:?}"
    );
    let files = human_box.audit_files();
    let skipped: Vec<_> = Sandbox::records(files.first().expect("audit file"))
        .into_iter()
        .filter_map(|r| match r.record {
            Record::Skipped { path, reason } => Some((path, reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        skipped,
        vec![(locked.clone(), "permission_denied".to_owned())],
        "one skipped record with the path and reason"
    );
    assert!(
        ok_file.exists() && allocated(&ok_file) > 0,
        "fixture sanity: the readable file exists"
    );

    assert_eq!(json.status.code(), Some(4), "json mode exits 4 too");
    let report = parse_json(&json.stdout);
    let rule = json_rule(&report, "user-caches");
    assert_eq!(rule["status"], "partial", "the rule is partial");
    assert_eq!(
        rule["bytes"].as_u64(),
        Some(allocated(&ok_json)),
        "only the readable file counts"
    );
    assert_eq!(
        rule["skipped_by_reason"]["permission_denied"], 1,
        "one denied entry"
    );
    let stderr = text(&json.stderr);
    let hints: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("Full Disk Access"))
        .collect();
    assert!(
        hints.len() == 1 && hints.iter().all(|l| l.contains("iTerm")),
        "in --json mode the single hint goes to stderr, got {hints:?}"
    );
    assert!(
        !text(&json.stdout).contains("Full Disk Access"),
        "stdout must stay pure JSON"
    );
}

/// # Design promise
/// AC-002-17 / INV-13: when the audit log cannot be opened the scan still runs and reports (it is
/// read-only), a warning is printed on **stderr** (so `--json` stdout stays pure), the report says
/// `audit_unavailable`, the exit code is 4, and the tool creates nothing in its place.
///
/// # Scenario (Given)
/// Test mode; `Library/Logs` is a regular *file* (the log directory cannot be created) and
/// `Library/Caches/app/blob` exists. Tree fingerprint taken before. Two runs: human and `--json`.
///
/// # Action (When)
/// `cleaner scan [--json] --rule user-caches`.
///
/// # Expected (Then)
/// Both exit 4; stderr mentions the audit log (case-insensitive `audit`); JSON stdout parses with
/// `audit_unavailable == true` and `user-caches.bytes == allocated(blob)`; human stdout still has the
/// `Safe` line; `Library/Logs` is unchanged (still the same regular file) and the fingerprint of the
/// whole tree is unchanged.
///
/// # Must never
/// Refuse to scan, exit 0, write the warning to stdout, or create the log somewhere else.
///
/// # Would catch
/// `?`-propagating the sink error out of `main`, silencing the warning, `mkdir -p` of a fallback
/// location, mixing the warning into the JSON stream.
///
/// # Why this test (not redundant)
/// Core tests the `None` sink; the file adapter tests `Unavailable`; only this proves the composition
/// root turns it into warning + stream routing + exit code.
#[test]
fn ac_002_17_an_unavailable_audit_log_warns_on_stderr_exits_4_and_the_scan_still_runs() {
    // Arrange
    let sandbox = Sandbox::new();
    let blob = sandbox.file("Library/Caches/app/blob", 8192);
    let logs = sandbox.file("Library/Logs", 5);
    let before = sandbox.tree_fingerprint();

    for json in [false, true] {
        // Act
        let mut cmd = sandbox.cleaner();
        cmd.arg("scan");
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .args(["--rule", "user-caches"])
            .output()
            .expect("run cleaner");

        // Assert
        let mode = if json { "json" } else { "human" };
        assert_eq!(
            out.status.code(),
            Some(4),
            "{mode}: unavailable audit exits 4; stderr: {}",
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).to_lowercase().contains("audit"),
            "{mode}: a warning about the audit log must go to stderr, got {:?}",
            text(&out.stderr)
        );
        if json {
            let report = parse_json(&out.stdout);
            assert_eq!(report["audit_unavailable"], true, "the report must say so");
            assert_eq!(
                json_rule(&report, "user-caches")["bytes"].as_u64(),
                Some(allocated(&blob)),
                "the scan must still run"
            );
        } else {
            assert!(
                line_starting(&text(&out.stdout), "Safe").contains("user-caches"),
                "the human report must still be printed"
            );
        }
        assert_eq!(
            fs::read_to_string(&logs).expect("Library/Logs is still a file"),
            "xxxxx",
            "{mode}: the blocking file must be untouched"
        );
        assert_eq!(
            sandbox.tree_fingerprint(),
            before,
            "{mode}: nothing may be created or changed"
        );
    }
}

/// # Design promise
/// AC-002-18: SIGINT sets the cancel token: the scan stops, reports `incomplete`/`interrupted`, writes
/// `run_end{interrupted: true, exit_code: 130}` to the audit log and the process exits **130** (it handles
/// the signal; it is not killed by it).
///
/// # Scenario (Given)
/// Test mode; the canned `tmutil` is a script that creates a `started` marker and then waits (polling)
/// for a `release` file. That makes the moment "the scan is running, before it walks any rule"
/// deterministic: the handler must already be installed when the marker appears. No timing assumptions
/// beyond a 15 s ceiling on waiting for the marker (the runner's own 10 s timeout also bounds the
/// script).
///
/// # Action (When)
/// Start `cleaner scan --json` in the background, wait for the marker, send `SIGINT` to the process
/// (`/bin/kill -INT <pid>`), then create `release`.
///
/// # Expected (Then)
/// Exit status code 130 (not a signal death); stdout is one JSON document with `interrupted == true`,
/// `incomplete == true` and every rule `interrupted`; the audit file's last record is `run_end` with
/// `exit_code 130` and `interrupted true`, and its first is `run_start` (one consistent run).
///
/// # Must never
/// Die from the signal without a `run_end` (INV-11: evidence of what happened), exit 0/4, or keep
/// scanning after the signal.
///
/// # Would catch
/// No handler (default SIGINT disposition kills the process), a handler installed after the scan
/// started, polling the token only after `run_scan`, mapping the interrupted report to exit 4.
///
/// # Why this test (not redundant)
/// Core proves cancellation at listing granularity with the token; this is the only test of the signal
/// handler wiring, the exit code 130 and the `run_end` on disk. The window is the deterministic
/// pre-walk one by design (a mid-walk signal would need timing).
#[test]
fn ac_002_18_sigint_stops_the_scan_exit_130_and_run_end_records_the_interruption() {
    // Arrange
    let sandbox = Sandbox::new();
    sandbox.file("Library/Caches/app/blob", 8192);
    let started = sandbox.bin.join("started");
    let release = sandbox.bin.join("release");
    sandbox.tmutil(&format!(
        "touch '{started}'\nwhile [ ! -e '{release}' ]; do /bin/sleep 0.05; done\nprintf 'Snapshots for disk /:\\n'",
        started = started.display(),
        release = release.display()
    ));
    let mut cmd = sandbox.std_command();
    cmd.args(["scan", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = common::KillOnDrop::spawn(&mut cmd);

    // Act
    let deadline = Instant::now() + Duration::from_secs(15);
    while !started.exists() {
        assert!(Instant::now() < deadline, "the scan never reached tmutil");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.send_sigint();
    fs::File::create(&release).expect("release the fake tmutil");
    let out = child.wait_with_output();

    // Assert
    assert_eq!(
        out.status.code(),
        Some(130),
        "a SIGINT must end the scan with exit code 130 (status {:?}); stderr: {}",
        out.status,
        text(&out.stderr)
    );
    let report = parse_json(&out.stdout);
    assert_eq!(
        report["interrupted"], true,
        "the report must say interrupted"
    );
    assert_eq!(report["incomplete"], true, "the report must say incomplete");
    assert!(
        report["rules"]
            .as_array()
            .is_some_and(|r| !r.is_empty() && r.iter().all(|x| x["status"] == "interrupted")),
        "no rule may have been walked after the signal: {}",
        report["rules"]
    );
    let files = sandbox.audit_files();
    let records = Sandbox::records(files.first().expect("audit file"));
    assert!(
        matches!(
            records.first().map(|r| &r.record),
            Some(Record::RunStart { .. })
        ),
        "the log of an interrupted run still starts with run_start"
    );
    assert!(
        matches!(
            records.last().map(|r| &r.record),
            Some(Record::RunEnd {
                exit_code: 130,
                interrupted: true,
                ..
            })
        ),
        "INV-11: the last record must be run_end(130, interrupted), got {:?}",
        records.last()
    );
}
