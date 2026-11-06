//! Rendering of a `ScanReport` for people and the byte-unit formatter (spec 002 AC-002-16, AC-002-2,
//! AC-002-7 hint, AC-002-18/-17 flags). Pure functions over canned reports: no process, no
//! filesystem. The wiring into the binary (stdout vs stderr, ANSI under a pipe) is in
//! `scan_cli.rs`.
//!
//! # Worksheet - `render::format_bytes`
//! ```text
//! Function:        cleaner_cli::render::format_bytes(u64) -> String
//! Contract:        base-10 units B, kB, MB, GB, TB, PB, EB; `N B` (integer) below 1000; otherwise one
//!                  decimal; the unit is the largest whose ROUNDED value is below 1000 (999 951 B is
//!                  `1.0 MB`, never `1000.0 kB`); the whole u64 range works. (AC-002-16)
//! Equivalence classes: bytes | each unit | rounding rollover | spec example values | u64::MAX
//! Boundaries:      999/1000 B; 999 949 vs 999 951 B (rounds to 999.9 kB vs rolls to 1.0 MB)
//! Must-never:      print `1000.0 <unit>`; panic or overflow on u64::MAX; use base-2 units
//! Selected tests:  ac_002_16_format_bytes_uses_base_10_units_with_one_decimal_and_rolls_over
//! Deliberately not tested: locale (none: ASCII digits and `.` only).
//! ```
//!
//! # Worksheet - `render::permission_hint`
//! ```text
//! Function:        cleaner_cli::render::permission_hint(&ScanReport, terminal_app) -> Option<String>
//! Contract:        Some(one line) iff some rule skipped an entry with reason `permission_denied`;
//!                  the line names the TERMINAL APP and says `Full Disk Access`; one line however many
//!                  rules or entries were denied; io_error / cross_device / refused never trigger it.
//!                  (AC-002-7, INV-09)
//! Equivalence classes: none denied | denied in one rule | denied in two rules | other skip reasons only
//! Must-never:      suggest privilege escalation or a retry; name the binary instead of the terminal
//! Selected tests:  ac_002_7_permission_hint_appears_once_and_only_for_permission_denied
//! Deliberately not tested: the exact wording beyond the two required tokens.
//! ```
//!
//! # Worksheet - `render::human`
//! ```text
//! Function:        cleaner_cli::render::human(&ScanReport, &HumanContext) -> String
//! Contract:        see the rustdoc of `human`: Volume line, Purgeable line (size, `macOS`, `not added`,
//!                  or `unknown` with no digit), snapshots line, tier lines with rule breakdown, the
//!                  hint once, `incomplete` when interrupted, Audit log line with path and run id (or
//!                  "unavailable"); no ANSI; never `recommend*`; `selected` only as `nothing selected`.
//!                  (AC-002-2, -3, -16, -17, -18, INV-02, INV-13)
//! Equivalence classes: fully known report | unknown volume+snapshots | interrupted / no audit log
//! Must-never:      print 0 for an unknown value; imply anything is selected or recommended; ANSI
//!                  Hardening: after the tier lines, EVERY rule with status refused / partial / interrupted
//!                  is listed as `<rule-id>: <status>` (+ skip reasons when known) even with 0 bytes;
//!                  ok / absent rules with 0 bytes appear in no tier line (INV-13: a failed rule must
//!                  not be invisible while the exit code says 4).
//! Selected tests:  ac_002_16_human_report_..., ac_002_2_human_report_..., ac_002_17_18_human_report_...,
//!                  ac_002_16_human_report_names_every_non_ok_rule_..._and_hides_zero_byte_ok_rules
//! Deliberately not tested: exact spacing/alignment and colors (tokens only, by design: the spec
//!                  fixes content, not layout).
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use cleaner_cli::render::{HumanContext, format_bytes, human, permission_hint};
use cleaner_core::report::{RuleReport, RuleStatus, SCHEMA, ScanReport, TierTotals, VolumeReport};
use cleaner_core::rules::Tier;

/// One rule report with `bytes` and the given skip tallies.
fn rule(id: &str, tier: Tier, status: RuleStatus, bytes: u64, skips: &[(&str, u64)]) -> RuleReport {
    let skipped_by_reason: BTreeMap<String, u64> =
        skips.iter().map(|(r, n)| ((*r).to_owned(), *n)).collect();
    RuleReport {
        id: id.to_owned(),
        tier,
        status,
        bytes,
        logical_bytes: bytes,
        items: u64::from(bytes > 0),
        skipped: skipped_by_reason.values().sum(),
        skipped_by_reason,
        vanished: 0,
        deduped_links: 0,
        top: Vec::new(),
    }
}

/// A fully known report modelled on the spec's example: volume 494.4/365.8 GB with 4.2 GB
/// purgeable, no snapshots, rules in three tiers, `ios-backups` denied.
fn known_report() -> ScanReport {
    let rules = vec![
        rule(
            "user-caches",
            Tier::Safe,
            RuleStatus::Ok,
            4_000_000_000,
            &[],
        ),
        rule(
            "cargo-cache",
            Tier::Safe,
            RuleStatus::Ok,
            1_200_000_000,
            &[],
        ),
        rule("trash", Tier::Safe, RuleStatus::Absent, 0, &[]),
        rule(
            "coresimulator",
            Tier::Caution,
            RuleStatus::Ok,
            8_100_000_000,
            &[],
        ),
        rule(
            "ios-backups",
            Tier::ReportOnly,
            RuleStatus::Partial,
            0,
            &[("permission_denied", 1)],
        ),
    ];
    ScanReport {
        schema: SCHEMA.to_owned(),
        run_id: "01J0000000000000000000RUN1".to_owned(),
        home: "/Users/u".to_owned(),
        home_b64: None,
        volume: VolumeReport {
            mount_point: Some("/System/Volumes/Data".to_owned()),
            total: Some(494_384_795_648),
            available: Some(365_789_609_984),
            available_important: Some(369_982_967_776),
            purgeable: Some(4_193_357_792),
            purgeable_clamped: false,
            volume_error: None,
        },
        snapshots: Some(Vec::new()),
        snapshots_unparsed: 0,
        snapshots_error: None,
        totals: TierTotals {
            safe: 5_200_000_000,
            caution: 8_100_000_000,
            report_only: 0,
        },
        rules,
        notes: Vec::new(),
        incomplete: false,
        interrupted: false,
        audit_unavailable: false,
    }
}

/// The first line of `text` whose first whitespace-separated token is `first`.
fn line_starting<'a>(text: &'a str, first: &str) -> &'a str {
    text.lines()
        .find(|l| l.split_whitespace().next() == Some(first))
        .unwrap_or_else(|| panic!("no line starts with `{first}` in:\n{text}"))
}

fn ctx(audit: Option<&str>) -> HumanContext {
    HumanContext {
        audit_log: audit.map(PathBuf::from),
        terminal_app: "iTerm".to_owned(),
    }
}

/// # Design promise
/// AC-002-16: sizes are shown in base-10 units (kB/MB/GB...) with one decimal, never base-2, never
/// `1000.0 <unit>`, with plain `N B` for small values; the whole `u64` range is formattable.
///
/// # Scenario (Given)
/// Rows: 0, 1, 999, 1000, 1500, 999 949, 999 951 (rounding rollover), the spec's purgeable and total
/// (4 193 357 792 and 494 384 795 648), 10^15, `u64::MAX`.
///
/// # Action (When)
/// `format_bytes` for each.
///
/// # Expected (Then)
/// `0 B`, `1 B`, `999 B`, `1.0 kB`, `1.5 kB`, `999.9 kB`, `1.0 MB` (999 951 rounds to 1000.0 kB, which
/// must roll over), `4.2 GB`, `494.4 GB`, `1.0 PB`, `18.4 EB`.
///
/// # Must never
/// Divide by 1024; print `1000.0`; panic or wrap on `u64::MAX`.
///
/// # Would catch
/// Base-2 units, `{:.1}` of a float without rollover, a missing EB unit (index out of range),
/// off-by-one at the 1000 boundary.
///
/// # Why this test (not redundant)
/// The only test of unit formatting; the report tests assert the formatted strings only for the spec's
/// example values.
#[test]
fn ac_002_16_format_bytes_uses_base_10_units_with_one_decimal_and_rolls_over() {
    // Arrange
    let rows: [(u64, &str); 11] = [
        (0, "0 B"),
        (1, "1 B"),
        (999, "999 B"),
        (1000, "1.0 kB"),
        (1500, "1.5 kB"),
        (999_949, "999.9 kB"),
        (999_951, "1.0 MB"),
        (4_193_357_792, "4.2 GB"),
        (494_384_795_648, "494.4 GB"),
        (1_000_000_000_000_000, "1.0 PB"),
        (u64::MAX, "18.4 EB"),
    ];

    for (bytes, want) in rows {
        // Act
        let got = format_bytes(bytes);

        // Assert
        assert_eq!(got, want, "format_bytes({bytes})");
    }
}

/// # Design promise
/// AC-002-7 / INV-09: when entries were denied by the OS the user gets a one-line hint to grant Full
/// Disk Access to the *terminal app* (not the binary); the hint is shown once however many rules were
/// affected, and only for `permission_denied` (other skip reasons have other causes).
///
/// # Scenario (Given)
/// Four reports: no skips; `permission_denied` in one rule; `permission_denied` in two rules (three
/// entries in total); only `io_error`, `cross_device` and a `refused` rule.
///
/// # Action (When)
/// `permission_hint(report, "iTerm")` for each.
///
/// # Expected (Then)
/// `None`; `Some(line)`; `Some(line)` (single line); `None`. Every `Some` line contains `iTerm` and
/// `Full Disk Access` and no newline.
///
/// # Must never
/// Show the hint for non-permission skips (misleading), show it twice, name no terminal app.
///
/// # Would catch
/// Triggering on any skip, counting hints per rule, forgetting the app name, multi-line output that
/// breaks the table.
///
/// # Why this test (not redundant)
/// The only test of the hint's trigger and shape; where it is printed (stdout vs stderr) is the CLI
/// test.
#[test]
fn ac_002_7_permission_hint_appears_once_and_only_for_permission_denied() {
    // Arrange
    let with = |rules: Vec<RuleReport>| ScanReport {
        rules,
        ..known_report()
    };
    let rows: Vec<(&str, ScanReport, bool)> = vec![
        (
            "no skips",
            with(vec![rule("a", Tier::Safe, RuleStatus::Ok, 10, &[])]),
            false,
        ),
        (
            "one rule denied",
            with(vec![rule(
                "a",
                Tier::Safe,
                RuleStatus::Partial,
                0,
                &[("permission_denied", 1)],
            )]),
            true,
        ),
        (
            "two rules denied, three entries",
            with(vec![
                rule(
                    "a",
                    Tier::Safe,
                    RuleStatus::Partial,
                    0,
                    &[("permission_denied", 2)],
                ),
                rule(
                    "b",
                    Tier::Caution,
                    RuleStatus::Partial,
                    0,
                    &[("permission_denied", 1)],
                ),
            ]),
            true,
        ),
        (
            "other reasons only",
            with(vec![
                rule("a", Tier::Safe, RuleStatus::Partial, 0, &[("io_error", 1)]),
                rule("b", Tier::Safe, RuleStatus::Ok, 0, &[("cross_device", 1)]),
                rule(
                    "c",
                    Tier::Safe,
                    RuleStatus::Refused,
                    0,
                    &[("root_refused", 1)],
                ),
            ]),
            false,
        ),
    ];

    for (name, report, want_hint) in rows {
        // Act
        let hint = permission_hint(&report, "iTerm");

        // Assert
        assert_eq!(hint.is_some(), want_hint, "{name}: hint presence");
        if let Some(line) = hint {
            assert!(
                line.contains("iTerm") && line.contains("Full Disk Access") && !line.contains('\n'),
                "{name}: one line naming the terminal app and Full Disk Access, got {line:?}"
            );
        }
    }
}

/// # Design promise
/// AC-002-16 / AC-002-3 / INV-02: the human report carries the volume, the OS-managed purgeable
/// number (marked as not added to the totals), snapshots, per-tier reclaimable totals with the rules
/// that contribute, the permission hint once, and the audit log path with the run id - and it never
/// marks anything selected or recommended, never uses ANSI escapes.
///
/// # Scenario (Given)
/// The spec's example report: 494.4 GB volume, 4.2 GB purgeable, zero snapshots, Safe 5.2 GB
/// (`user-caches` 4.0, `cargo-cache` 1.2, `trash` absent), Caution 8.1 GB (`coresimulator`),
/// Report-only 0 B (`ios-backups`, permission denied), audit log `/Users/u/Library/Logs/mac-cleaner/audit-2026-11-06.jsonl`.
///
/// # Action (When)
/// `human(report, ctx)` with terminal app `iTerm`.
///
/// # Expected (Then)
/// The `Volume` line has the mount point, `total 494.4 GB`, `available 365.8 GB`; the `Purgeable` line
/// has `4.2 GB`, `macOS` and `not added`; a `Local snapshots: 0` line; tier lines `Safe` (5.2 GB,
/// `user-caches 4.0 GB`, `cargo-cache 1.2 GB`), `Caution` (8.1 GB, `coresimulator 8.1 GB`),
/// `Report-only` (0 B, `ios-backups`, `permission denied`); exactly one line with `Full Disk Access`
/// naming `iTerm`; an `Audit log:` line with the path and `run 01J0000000000000000000RUN1`; the text
/// says `nothing selected`; no ESC byte; no `recommend`; every `selected` is part of `nothing selected`.
///
/// # Must never
/// Add purgeable to a tier total; say anything is selected or recommended (INV-02); emit ANSI; repeat
/// the hint per rule.
///
/// # Would catch
/// A renderer that prints raw byte counts, drops the "not added" disclaimer (users would sum purgeable
/// and reclaimable), a "recommended" column, colors without a TTY check.
///
/// # Why this test (not redundant)
/// The only test of the human layout's content for a known report; unknown values and the
/// interrupted/unavailable flags are the next two tests.
#[test]
fn ac_002_16_human_report_shows_volume_purgeable_tiers_hint_and_audit_and_never_selects() {
    // Arrange
    let report = known_report();
    let log = "/Users/u/Library/Logs/mac-cleaner/audit-2026-11-06.jsonl";

    // Act
    let text = human(&report, &ctx(Some(log)));

    // Assert
    let volume = line_starting(&text, "Volume");
    assert!(
        volume.contains("/System/Volumes/Data")
            && volume.contains("total 494.4 GB")
            && volume.contains("available 365.8 GB"),
        "Volume line: {volume:?}"
    );
    let purge = line_starting(&text, "Purgeable");
    assert!(
        purge.contains("4.2 GB") && purge.contains("macOS") && purge.contains("not added"),
        "Purgeable line must show the size, say macOS manages it and that it is not added: {purge:?}"
    );
    assert!(
        text.lines().any(|l| l.trim() == "Local snapshots: 0"),
        "a `Local snapshots: 0` line is expected in:\n{text}"
    );
    let safe = line_starting(&text, "Safe");
    assert!(
        safe.contains("5.2 GB")
            && safe.contains("user-caches 4.0 GB")
            && safe.contains("cargo-cache 1.2 GB"),
        "Safe tier line: {safe:?}"
    );
    let caution = line_starting(&text, "Caution");
    assert!(
        caution.contains("8.1 GB") && caution.contains("coresimulator 8.1 GB"),
        "Caution tier line: {caution:?}"
    );
    let report_only = line_starting(&text, "Report-only");
    assert!(
        report_only.contains("0 B")
            && report_only.contains("ios-backups")
            && report_only.contains("permission denied"),
        "Report-only tier line: {report_only:?}"
    );
    let hints: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("Full Disk Access"))
        .collect();
    assert!(
        hints.len() == 1 && hints.iter().all(|l| l.contains("iTerm")),
        "exactly one Full Disk Access hint naming the terminal app, got {hints:?}"
    );
    let audit = line_starting(&text, "Audit");
    assert!(
        audit.contains(log) && audit.contains("run 01J0000000000000000000RUN1"),
        "Audit log line must show the path and the run id: {audit:?}"
    );
    let lower = text.to_lowercase();
    assert!(
        lower.contains("nothing selected"),
        "INV-02: the report must say nothing is selected"
    );
    assert!(
        !lower.contains("recommend"),
        "INV-02: nothing may be recommended:\n{text}"
    );
    assert_eq!(
        lower.matches("selected").count(),
        lower.matches("nothing selected").count(),
        "INV-02: `selected` may only appear as `nothing selected`"
    );
    assert!(
        !text.contains('\u{1b}'),
        "no ANSI escape sequences in the plain report"
    );
}

/// # Design promise
/// AC-002-2 / INV-13: an unknown purgeable value or snapshot list is shown as `unknown` - never as `0`
/// or `0 B` - and the rest of the report is still produced.
///
/// # Scenario (Given)
/// The example report with the volume query failed (`volume_error: "query_failed"`, every volume number
/// `None`) and `tmutil` failed (`snapshots: None`, `snapshots_error: "tool_missing"`).
///
/// # Action (When)
/// `human(report, ctx)`.
///
/// # Expected (Then)
/// The `Purgeable` line contains `unknown` and not a single ASCII digit; the `Local snapshots` line
/// contains `unknown`; the tier lines (known rule results) are still present.
///
/// # Must never
/// Print `0`/`0 B` for an unknown value (INV-13: unknown is not none).
///
/// # Would catch
/// `purgeable.unwrap_or(0)` and `format_bytes` of a defaulted number, `snapshots.len()` on an unknown
/// list.
///
/// # Why this test (not redundant)
/// The only rendering test of the unknown class; the null-not-zero JSON is core-tested.
#[test]
fn ac_002_2_human_report_says_unknown_never_zero_when_volume_or_snapshots_are_unknown() {
    // Arrange
    let mut report = known_report();
    report.volume = VolumeReport {
        mount_point: None,
        total: None,
        available: None,
        available_important: None,
        purgeable: None,
        purgeable_clamped: false,
        volume_error: Some("query_failed".to_owned()),
    };
    report.snapshots = None;
    report.snapshots_error = Some("tool_missing".to_owned());

    // Act
    let text = human(&report, &ctx(Some("/x/audit.jsonl")));

    // Assert
    let purge = line_starting(&text, "Purgeable");
    assert!(
        purge.contains("unknown") && !purge.bytes().any(|b| b.is_ascii_digit()),
        "INV-13: unknown purgeable must read `unknown` with no number at all: {purge:?}"
    );
    let snaps = line_starting(&text, "Local");
    assert!(
        snaps.contains("unknown"),
        "unknown snapshot list must read `unknown`: {snaps:?}"
    );
    assert!(
        text.lines()
            .any(|l| l.split_whitespace().next() == Some("Safe")),
        "the known rule results must still be shown:\n{text}"
    );
}

/// # Design promise
/// AC-002-18 / AC-002-17: an interrupted scan is labelled `incomplete` (its numbers are partial), a
/// finished one is not; when the audit log could not be opened the report says so instead of printing
/// a path.
///
/// # Scenario (Given)
/// Rows: (interrupted report, log present), (complete report, log absent).
///
/// # Action (When)
/// `human(report, ctx)`.
///
/// # Expected (Then)
/// Row 1: contains `incomplete` (case-insensitive) and the `Audit log:` line has the path. Row 2: no
/// `incomplete`; the `Audit` line contains `unavailable` and no path.
///
/// # Must never
/// Present partial numbers of an interrupted run as final; print a log path that does not exist.
///
/// # Would catch
/// Ignoring `report.interrupted`; unconditional `Audit log: {path}` with an empty path.
///
/// # Why this test (not redundant)
/// The only rendering test of the two status flags.
#[test]
fn ac_002_18_human_report_flags_incomplete_runs_and_an_unavailable_audit_log() {
    // Arrange
    let interrupted = ScanReport {
        incomplete: true,
        interrupted: true,
        ..known_report()
    };
    let complete = known_report();

    // Act
    let first = human(&interrupted, &ctx(Some("/x/audit.jsonl")));
    let second = human(&complete, &ctx(None));

    // Assert
    assert!(
        first.to_lowercase().contains("incomplete"),
        "an interrupted scan must be labelled incomplete:\n{first}"
    );
    assert!(
        line_starting(&first, "Audit").contains("/x/audit.jsonl"),
        "the log path must be shown when a log exists"
    );
    assert!(
        !second.to_lowercase().contains("incomplete"),
        "a finished scan must not be labelled incomplete:\n{second}"
    );
    assert!(
        line_starting(&second, "Audit").contains("unavailable"),
        "a missing audit log must be reported as unavailable:\n{second}"
    );
}

/// # Design promise
/// Hardening round (AC-002-16, INV-13, exit-code policy of AC-002-7): a rule that did not complete
/// (`refused`, `partial`, `interrupted`) makes the exit code 4/130, so the human report must say WHICH
/// rule it was, even when it contributed 0 bytes (a refused rule scans nothing). After the tier lines
/// the report lists each such rule as `<rule-id>: <status>`, followed by its skip reasons when known
/// (`root_refused`, `permission_denied`). Conversely a rule that is `ok` or `absent` with 0 bytes is
/// not news and stays out of the tier lines.
///
/// # Scenario (Given)
/// `known_report()` (`ios-backups` partial with `permission_denied`, 0 bytes; `trash` absent, 0 bytes;
/// other rules ok with bytes) plus three rules, all 0 bytes: `docker-data` (Safe, `refused`,
/// `root_refused` 1), `xcode-derived` (Caution, `interrupted`, no skips), and `empty-ok` (Safe, `ok`,
/// no skips: the 0-byte ok class, besides the absent `trash`).
///
/// # Action (When)
/// `human(report, ctx)`.
///
/// # Expected (Then)
/// Each of `docker-data`, `xcode-derived`, `ios-backups` has a line (found by its first token
/// `<id>:`) that starts `<id>: <status>` (`refused`, `interrupted`, `partial`), placed after the
/// `Report-only` tier line; the `docker-data` line also names `root_refused` and the `ios-backups`
/// line `permission_denied`. No tier line (`Safe`, `Caution`, `Report-only`) mentions `trash` or
/// `empty-ok`, and no line starts with `trash:`, `empty-ok:` or `user-caches:` (ok/absent rules are
/// never listed as problems). The rule that has bytes keeps its tier-line entry.
///
/// # Must never
/// Hide a refused/interrupted rule because its bytes are 0; list an ok/absent rule as a problem; list
/// an ok/absent 0-byte rule in a tier line (`bytes > 0` weakened to `bytes >= 0`).
///
/// # Would catch
/// The shipped bug (tier lines filter on `bytes > 0`, so `refused` rules vanish while exit is 4); the
/// mutant `r.bytes > 0` -> `r.bytes >= 0` in `tier_line`; listing statuses without their reasons; the
/// problem list printed before the tier lines.
///
/// # Why this test (not redundant)
/// The only test of the non-ok listing and the only negative assertion on zero-byte ok/absent rules;
/// the example-report test above covers the happy tier lines and the `permission denied` marker.
#[test]
fn ac_002_16_human_report_names_every_non_ok_rule_after_the_tiers_and_hides_zero_byte_ok_rules() {
    // Arrange
    let mut report = known_report();
    report.rules.extend([
        rule(
            "docker-data",
            Tier::Safe,
            RuleStatus::Refused,
            0,
            &[("root_refused", 1)],
        ),
        rule(
            "xcode-derived",
            Tier::Caution,
            RuleStatus::Interrupted,
            0,
            &[],
        ),
        rule("empty-ok", Tier::Safe, RuleStatus::Ok, 0, &[]),
    ]);

    // Act
    let text = human(&report, &ctx(Some("/x/audit.jsonl")));

    // Assert
    let lines: Vec<&str> = text.lines().collect();
    let position = |first: &str| {
        lines
            .iter()
            .position(|l| l.split_whitespace().next() == Some(first))
    };
    let last_tier = position("Report-only").expect("the Report-only tier line");
    for (id, status, reason) in [
        ("docker-data", "refused", Some("root_refused")),
        ("xcode-derived", "interrupted", None),
        ("ios-backups", "partial", Some("permission_denied")),
    ] {
        let at = position(&format!("{id}:"))
            .unwrap_or_else(|| panic!("INV-13: no `{id}: {status}` line in the report:\n{text}"));
        let line = lines[at].trim_start();
        assert!(
            line.starts_with(&format!("{id}: {status}")),
            "`{id}` must read `{id}: {status}`, got {line:?}"
        );
        assert!(
            at > last_tier,
            "`{id}` must be listed after the tier lines (line {at} vs Report-only at {last_tier})"
        );
        if let Some(reason) = reason {
            assert!(
                line.contains(reason),
                "`{id}` must name its skip reason `{reason}`: {line:?}"
            );
        }
    }
    for tier in ["Safe", "Caution", "Report-only"] {
        let line = line_starting(&text, tier);
        assert!(
            !line.contains("trash") && !line.contains("empty-ok"),
            "{tier} tier line must not list 0-byte ok/absent rules: {line:?}"
        );
    }
    assert!(
        line_starting(&text, "Safe").contains("user-caches 4.0 GB"),
        "rules with bytes keep their tier-line entry"
    );
    for quiet in [
        "trash:",
        "empty-ok:",
        "user-caches:",
        "cargo-cache:",
        "coresimulator:",
    ] {
        assert!(
            position(quiet).is_none(),
            "ok/absent rule `{quiet}` must not be listed as a problem:\n{text}"
        );
    }
}
