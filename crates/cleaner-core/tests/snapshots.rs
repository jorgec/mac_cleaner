//! Local Time Machine snapshots: `tmutil` output parsing, the read-only invocation, and failure
//! reporting (spec 002 AC-002-21; INV-10, INV-13). The real `tmutil` adapter is slice 002b.
//!
//! # Worksheet - `snapshots::parse_listlocalsnapshots`
//! ```text
//! Function:        parse_listlocalsnapshots(&str) -> ParsedSnapshots{snapshots, unparsed}
//! Contract:        names `com.apple.TimeMachine.<YYYY-MM-DD-HHMMSS>.local` -> {name, date, bytes:null};
//!                  the `Snapshots for ...:` header and blank lines are not snapshots; every other
//!                  line is kept as {name: line, date: null} and counted in `unparsed`; real calendar
//!                  and time-of-day only; output order preserved; zero snapshots -> []. (AC-002-21)
//! Equivalence classes: header only (real captured output) | empty | valid names | foreign line |
//!                  impossible date/time | leap days | near-miss pattern | padding/blank lines
//! Boundaries:      Feb 29 in leap (2024, 2000) vs non-leap (2100) years; hour 24, minute 60,
//!                  second 60; 5-digit time; trailing text after `.local`
//! Must-never:      treat the header as a snapshot; invent a size; drop an unrecognized line
//!                  silently; reorder
//! Selected tests:  ac_002_21_parser_...
//! Deliberately not tested: non-UTF-8 stdout (the caller decodes lossily; no contract), very
//!                  large outputs.
//! ```
//!
//! # Worksheet - `snapshots::list_local_snapshots` and the scan wiring
//! ```text
//! Function:        list_local_snapshots(&dyn CommandRunner); run_scan (snapshot part)
//! Contract:        exactly one runner call: `/usr/bin/tmutil` with args ["listlocalsnapshots","/"]
//!                  and a 10 s timeout, never sudo, never a mutating tmutil verb; tool missing /
//!                  timeout / spawn failure / non-zero exit -> Err(kind) which the scan reports as
//!                  `snapshots: null` + `snapshots_error` + exit 4 (unknown is not empty); success
//!                  with >= 1 snapshot adds the note `snapshot_sizes_unavailable`; zero snapshots
//!                  is `[]`, no note, no error. (AC-002-21, INV-10, INV-13)
//! Equivalence classes: ok(0) | ok(n) | NotFound | TimedOut | Failed | non-zero exit
//! Boundaries:      empty list vs unknown list
//! Must-never:      `sudo`; `delete*`/`thinlocalsnapshots`; report a failure as an empty list
//! Selected tests:  see fns below
//! Deliberately not tested: the process-level exit code plumbing (CLI, 002b).
//! ```

mod common;

use std::time::Duration;

use cleaner_core::ports::CommandError;
use cleaner_core::report::{NOTE_SNAPSHOT_SIZES_UNAVAILABLE, ScanReport};
use cleaner_core::rules::Rule;
use cleaner_core::snapshots::{SnapshotsError, list_local_snapshots, parse_listlocalsnapshots};
use cleaner_testkit::{FakeFs, FakeRunner};
use common::{TMUTIL_NO_SNAPSHOTS, harness};

const GOOD_1: &str = "com.apple.TimeMachine.2026-11-06-123456.local";
const GOOD_2: &str = "com.apple.TimeMachine.2024-02-29-235959.local";

/// # Design promise
/// AC-002-21: `tmutil listlocalsnapshots /` output is parsed into `{name, date, bytes: null}`;
/// zero snapshots is `[]` (the real header-only output must not become a bogus entry); lines that
/// are not recognizable snapshot names are kept (`date: null`) and counted in `unparsed`; only real
/// calendar dates and times of day get a date.
///
/// # Scenario (Given)
/// Rows `(name, stdout, expected [(name, date)], expected unparsed)`: the real header-only output;
/// empty output; a volume-group header plus two valid names (order preserved); a foreign line
/// between valid ones; header look-alikes (`Snapshots for disk /` without the colon, `list:`);
/// wrong separators/letters in a name of the right length; month lengths (31 Dec and 28 Feb 2026 valid, 31 Apr,
/// month 0, day 0 invalid); impossible dates (Feb 30, month 13, hour 24, minute 60, second 60, Feb 29 of
/// non-leap 2100); leap days that are real (2024, 2000); near-miss patterns (5-digit time, suffix
/// after `.local`, prefix before `com.`); padding, CRLF and blank lines.
///
/// # Action (When)
/// `parse_listlocalsnapshots(stdout)` per row.
///
/// # Expected (Then)
/// Exactly the expected `(name, date)` sequence (dates as `YYYY-MM-DDTHH:MM:SS`), `unparsed`
/// equals the number of `date: None` entries, and every `bytes` is `None` (tmutil reports no sizes).
///
/// # Must never
/// Count the header as a snapshot or as unparsed; give a date to an impossible time; invent a size.
///
/// # Would catch
/// A parser that only splits on newlines (header becomes an entry), validates digits but not the
/// calendar (Feb 30 accepted), treats every century year divisible by 4 as leap, or uses
/// `contains` instead of an exact pattern.
///
/// # Why this test (not redundant)
/// The only coverage of the parsing half of AC-002-21; the invocation and failure outcomes are the
/// next tests.
#[test]
#[allow(clippy::too_many_lines, reason = "table rows")]
fn ac_002_21_parser_names_dates_unparsed_and_the_header_are_handled() {
    // Arrange
    type Row<'a> = (&'a str, String, Vec<(&'a str, Option<&'a str>)>, u64);
    let rows: Vec<Row<'_>> = vec![
        ("real header-only output", TMUTIL_NO_SNAPSHOTS.to_owned(), vec![], 0),
        ("empty output", String::new(), vec![], 0),
        (
            "volume-group header and two names",
            format!("Snapshots for volume group containing disk /:\n{GOOD_1}\n{GOOD_2}\n"),
            vec![
                (GOOD_1, Some("2026-11-06T12:34:56")),
                (GOOD_2, Some("2024-02-29T23:59:59")),
            ],
            0,
        ),
        (
            "foreign line is kept and counted",
            format!("{GOOD_1}\nsomething.else\n{GOOD_2}\n"),
            vec![
                (GOOD_1, Some("2026-11-06T12:34:56")),
                ("something.else", None),
                (GOOD_2, Some("2024-02-29T23:59:59")),
            ],
            1,
        ),
        (
            "impossible dates and times",
            [
                "com.apple.TimeMachine.2026-02-30-120000.local",
                "com.apple.TimeMachine.2026-13-01-000000.local",
                "com.apple.TimeMachine.2026-01-01-240000.local",
                "com.apple.TimeMachine.2026-01-01-006000.local",
                "com.apple.TimeMachine.2026-01-01-000060.local",
                "com.apple.TimeMachine.2100-02-29-000000.local",
            ]
            .join("\n"),
            vec![
                ("com.apple.TimeMachine.2026-02-30-120000.local", None),
                ("com.apple.TimeMachine.2026-13-01-000000.local", None),
                ("com.apple.TimeMachine.2026-01-01-240000.local", None),
                ("com.apple.TimeMachine.2026-01-01-006000.local", None),
                ("com.apple.TimeMachine.2026-01-01-000060.local", None),
                ("com.apple.TimeMachine.2100-02-29-000000.local", None),
            ],
            6,
        ),
        (
            "real leap days",
            "com.apple.TimeMachine.2000-02-29-000000.local\ncom.apple.TimeMachine.2024-02-29-000000.local".to_owned(),
            vec![
                ("com.apple.TimeMachine.2000-02-29-000000.local", Some("2000-02-29T00:00:00")),
                ("com.apple.TimeMachine.2024-02-29-000000.local", Some("2024-02-29T00:00:00")),
            ],
            0,
        ),
        (
            "near-miss patterns",
            [
                "com.apple.TimeMachine.2026-11-06-12345.local",
                "com.apple.TimeMachine.2026-11-06-123456.local.extra",
                "x.com.apple.TimeMachine.2026-11-06-123456.local",
            ]
            .join("\n"),
            vec![
                ("com.apple.TimeMachine.2026-11-06-12345.local", None),
                ("com.apple.TimeMachine.2026-11-06-123456.local.extra", None),
                ("x.com.apple.TimeMachine.2026-11-06-123456.local", None),
            ],
            3,
        ),
        (
            "header look-alikes are not headers",
            "Snapshots for disk /\nlist:\n".to_owned(),
            vec![("Snapshots for disk /", None), ("list:", None)],
            2,
        ),
        (
            "wrong separators or letters in a right-length name",
            [
                "com.apple.TimeMachine.2026x11-06-123456.local",
                "com.apple.TimeMachine.2026-11x06-123456.local",
                "com.apple.TimeMachine.2026-11-06x123456.local",
                "com.apple.TimeMachine.2026-11-06-12a456.local",
            ]
            .join("\n"),
            vec![
                ("com.apple.TimeMachine.2026x11-06-123456.local", None),
                ("com.apple.TimeMachine.2026-11x06-123456.local", None),
                ("com.apple.TimeMachine.2026-11-06x123456.local", None),
                ("com.apple.TimeMachine.2026-11-06-12a456.local", None),
            ],
            4,
        ),
        (
            "month lengths: 31-day month valid, 30-day month rejects the 31st, zero month/day",
            [
                "com.apple.TimeMachine.2025-12-31-235959.local",
                "com.apple.TimeMachine.2026-04-31-000000.local",
                "com.apple.TimeMachine.2026-00-10-000000.local",
                "com.apple.TimeMachine.2026-01-00-000000.local",
            ]
            .join("\n"),
            vec![
                ("com.apple.TimeMachine.2025-12-31-235959.local", Some("2025-12-31T23:59:59")),
                ("com.apple.TimeMachine.2026-04-31-000000.local", None),
                ("com.apple.TimeMachine.2026-00-10-000000.local", None),
                ("com.apple.TimeMachine.2026-01-00-000000.local", None),
            ],
            3,
        ),
        (
            "valid non-leap February: the 28th is a real day (the month is 28 days long, not 29)",
            "com.apple.TimeMachine.2026-02-28-120000.local".to_owned(),
            vec![(
                "com.apple.TimeMachine.2026-02-28-120000.local",
                Some("2026-02-28T12:00:00"),
            )],
            0,
        ),
        (
            "padding, CRLF and blank lines",
            format!("\r\n  {GOOD_1}  \r\n\n\t\n"),
            vec![(GOOD_1, Some("2026-11-06T12:34:56"))],
            0,
        ),
    ];

    for (name, stdout, want, want_unparsed) in rows {
        // Act
        let parsed = parse_listlocalsnapshots(&stdout);

        // Assert
        let got: Vec<(&str, Option<&str>)> = parsed
            .snapshots
            .iter()
            .map(|s| (s.name.as_str(), s.date.as_deref()))
            .collect();
        assert_eq!(got, want, "row `{name}`: (name, date) sequence");
        assert_eq!(
            parsed.unparsed, want_unparsed,
            "row `{name}`: unparsed count"
        );
        assert!(
            parsed.snapshots.iter().all(|s| s.bytes.is_none()),
            "row `{name}`: tmutil reports no sizes, so bytes must be None (never a guess)"
        );
    }
}

/// # Design promise
/// AC-002-21 / INV-10: the tool is run through the port as an argument array with a 10 s timeout,
/// read-only and without privilege escalation; the output is parsed; no mutating `tmutil` verb and
/// no `sudo` ever reach the runner.
///
/// # Scenario (Given)
/// A `FakeRunner` answering exit 0 with two snapshot names.
///
/// # Action (When)
/// `list_local_snapshots(&runner)`.
///
/// # Expected (Then)
/// `Ok` with the two parsed snapshots; exactly one runner call; program is `tmutil` (absolute
/// path), args `["listlocalsnapshots", "/"]`, timeout 10 s.
///
/// # Must never
/// Call `sudo`, any `delete*` / `thinlocalsnapshots` verb, or a second command.
///
/// # Would catch
/// Passing the command as one shell string, a missing/long timeout (hangs the scan), `tmutil
/// deletelocalsnapshots` slipping in, privilege escalation (INV-10).
///
/// # Why this test (not redundant)
/// The only test of the invocation contract; the failure kinds are the next test.
#[test]
fn safety_ac_002_21_tmutil_is_invoked_read_only_with_args_array_and_timeout() {
    // Arrange
    let runner = FakeRunner::ok(&format!("Snapshots for disk /:\n{GOOD_1}\n{GOOD_2}\n"));

    // Act
    let result = list_local_snapshots(&runner);

    // Assert
    let parsed = result.expect("a successful tmutil run must be Ok");
    assert_eq!(parsed.snapshots.len(), 2, "both snapshots must be parsed");
    let calls = runner.calls();
    assert_eq!(
        calls.len(),
        1,
        "exactly one command may be run, got {calls:?}"
    );
    let call = &calls[0];
    assert!(
        call.program == "tmutil" || call.program.ends_with("/tmutil"),
        "the program must be tmutil, got {:?}",
        call.program
    );
    assert_eq!(
        call.args,
        ["listlocalsnapshots", "/"],
        "args must be an array, read-only verb"
    );
    assert_eq!(
        call.timeout,
        Duration::from_secs(10),
        "AC-002-21: 10 s timeout"
    );
    assert!(
        !call.program.contains("sudo")
            && !call
                .args
                .iter()
                .any(|a| a.starts_with("delete") || a.contains("thin") || a == "sudo"),
        "INV-10: no sudo and no mutating tmutil verb, got {call:?}"
    );
}

/// # Design promise
/// AC-002-21 / INV-13: when `tmutil` cannot give an answer, the list is **unknown**, with a stable
/// error kind - never an empty list.
///
/// # Scenario (Given)
/// Runners failing with `NotFound`, `TimedOut`, `Failed`, and a runner whose command exits 1.
///
/// # Action (When)
/// `list_local_snapshots(&runner)` per row.
///
/// # Expected (Then)
/// `Err(e)` with `e.kind()` == `tool_missing`, `timeout`, `spawn_failed`, `nonzero_exit`
/// respectively.
///
/// # Must never
/// Return `Ok` with an empty list for a failure.
///
/// # Would catch
/// `unwrap_or_default()` on the runner result, treating a non-zero exit with empty stdout as "zero
/// snapshots", conflating timeout with missing tool.
///
/// # Why this test (not redundant)
/// The only coverage of the failure outcomes at the function level; the scan-level test checks the
/// report wiring for one of them.
#[test]
fn ac_002_21_tool_failures_are_errors_with_stable_kinds_not_empty_lists() {
    // Arrange
    let rows = [
        (FakeRunner::failing(CommandError::NotFound), "tool_missing"),
        (FakeRunner::failing(CommandError::TimedOut), "timeout"),
        (
            FakeRunner::failing(CommandError::Failed {
                reason: "spawn".to_owned(),
            }),
            "spawn_failed",
        ),
        (FakeRunner::exit(1, "tmutil: error"), "nonzero_exit"),
    ];

    for (runner, want_kind) in rows {
        // Act
        let result = list_local_snapshots(&runner);

        // Assert
        let kind = result.as_ref().map_err(SnapshotsError::kind).err();
        assert_eq!(
            kind,
            Some(want_kind),
            "INV-13: failure `{want_kind}` must be an Err with that kind, got {result:?}"
        );
    }
}

/// # Design promise
/// AC-002-21 / AC-002-20: the scan reports the snapshot list as known-empty, known-non-empty (with
/// `unparsed` and the `snapshot_sizes_unavailable` note), or unknown (`null` + error kind + exit 4).
///
/// # Scenario (Given)
/// Three runs on an empty home: header-only output; output with two valid names and one foreign
/// line; a missing `tmutil`.
///
/// # Action (When)
/// `run_scan` with no rules.
///
/// # Expected (Then)
/// Row 1: `snapshots == Some([])`, no error, no sizes note, `exit_code() == 0`. Row 2: two named
/// snapshots plus the foreign one kept (3 entries), `snapshots_unparsed == 1`, every `bytes` null,
/// the note present. Row 3: `snapshots == None`, `snapshots_error == "tool_missing"`, no sizes note,
/// `exit_code() == 4`.
///
/// # Must never
/// Report an unknown list as `[]`; emit the sizes note when there are no snapshots or no answer.
///
/// # Would catch
/// A scan that swallows the runner error into an empty list, a note emitted unconditionally, an
/// `unparsed` count lost between the parser and the report.
///
/// # Why this test (not redundant)
/// The only test of the snapshot -> report wiring; parser and runner contracts are tested above.
#[test]
fn ac_002_21_scan_reports_snapshots_as_empty_listed_or_unknown() {
    // Arrange
    let listed = format!("Snapshots for disk /:\n{GOOD_1}\nweird\n{GOOD_2}\n");
    let rows = [
        ("zero snapshots", FakeRunner::ok(TMUTIL_NO_SNAPSHOTS)),
        ("listed", FakeRunner::ok(&listed)),
        ("tool missing", FakeRunner::failing(CommandError::NotFound)),
    ];

    for (name, runner) in rows {
        let h = harness(FakeFs::builder().dir("/Users/u").build()).with_runner(runner);

        // Act
        let report: ScanReport = h.scan(&[] as &[Rule], 5);

        // Assert
        let has_note = report
            .notes
            .iter()
            .any(|n| n == NOTE_SNAPSHOT_SIZES_UNAVAILABLE);
        match name {
            "zero snapshots" => {
                assert_eq!(report.snapshots, Some(vec![]), "{name}: known empty list");
                assert_eq!(report.snapshots_error, None, "{name}: no error");
                assert!(!has_note, "{name}: nothing to size, so no sizes note");
                assert_eq!(report.exit_code(), 0, "{name}: a clean scan exits 0");
            }
            "listed" => {
                let list = report.snapshots.as_ref();
                assert_eq!(list.map(Vec::len), Some(3), "{name}: all lines kept");
                assert_eq!(
                    report.snapshots_unparsed, 1,
                    "{name}: the foreign line is counted"
                );
                assert!(
                    list.is_some_and(|l| l.iter().all(|s| s.bytes.is_none())),
                    "{name}: sizes are unknown (null), never invented"
                );
                assert!(
                    has_note,
                    "{name}: AC-002-21 the sizes-unavailable note must be emitted"
                );
            }
            _ => {
                assert_eq!(report.snapshots, None, "{name}: INV-13 unknown, not empty");
                assert_eq!(
                    report.snapshots_error.as_deref(),
                    Some("tool_missing"),
                    "{name}: error kind"
                );
                assert!(!has_note, "{name}: no snapshots known, no sizes note");
                assert_eq!(
                    report.exit_code(),
                    4,
                    "{name}: unknown snapshots are a partial result"
                );
            }
        }
    }
}
