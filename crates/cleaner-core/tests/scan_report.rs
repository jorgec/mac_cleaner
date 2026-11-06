//! The `scan/1` report contract: schema and key order, honesty notes, `path`/`path_b64`, tier
//! totals and the exit-code policy (spec 002 AC-002-16, AC-002-20, AC-002-9 vocabulary; INV-12,
//! INV-13, INV-16). Human rendering and `--json` plumbing are CLI work (slice 002b).
//!
//! # Worksheet - `report::ScanReport` (serialization, notes, totals, exit code)
//! ```text
//! Function:        ScanReport (serde), ScanReport::exit_code(), run_scan notes/totals
//! Contract:        JSON keys and their order are the schema `scan/1` (volume, snapshots, rules with
//!                  top entries, totals per tier, notes, flags); `notes` always holds the four
//!                  honesty codes in spec order plus `snapshot_sizes_unavailable` when snapshots are
//!                  listed; non-UTF-8 paths are lossy `path` + `path_b64` (raw bytes, base64) only
//!                  when lossy; totals = per-tier sums of rule bytes; exit code: 130 interrupted >
//!                  4 partial/unknown (partial or refused rule, unknown purgeable or snapshots,
//!                  audit unavailable) > 0 (absent roots and vanished entries are fine).
//! Equivalence classes: key schema | notes with/without snapshots | utf-8 vs non-utf-8 path |
//!                  tiers | each exit-code trigger
//! Boundaries:      `path_b64` present vs absent; absent/vanished must NOT raise the exit code
//! Must-never:      renaming/reordering keys without a schema bump; prose in `notes`; `path_b64` on
//!                  clean UTF-8 paths; summing purgeable into totals
//! Selected tests:  see fns below
//! Deliberately not tested: serde derive behavior itself; exact tokens of notes beyond the codes;
//!                  human formatting, NO_COLOR, units (CLI, 002b).
//! ```

mod common;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use base64::Engine as _;
use cleaner_core::report::{
    NOTE_CLONE_OVERCOUNT, NOTE_NOT_ADDITIVE, NOTE_PURGEABLE_OS_MANAGED,
    NOTE_SNAPSHOT_SIZES_UNAVAILABLE, NOTE_TRASH_FREES_NOTHING, RuleStatus, ScanReport,
};
use cleaner_core::rules::{Rule, Tier};
use cleaner_testkit::{FakeFs, FakeRunner};
use common::{TMUTIL_NO_SNAPSHOTS, blocks, harness, home, rule_report};

/// Every `(depth, key)` of a JSON text in document order. `depth` is the number of enclosing
/// objects/arrays (the top-level object's keys have depth 1). Used to pin key names *and order*
/// without a snapshot crate.
fn key_sequence(json: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = json.chars().collect();
    let (mut depth, mut i, mut keys) = (0_usize, 0_usize, Vec::new());
    while i < chars.len() {
        match chars[i] {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            '"' => {
                let mut s = String::new();
                i += 1;
                while chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    s.push(chars[i]);
                    i += 1;
                }
                if chars.get(i + 1) == Some(&':') {
                    keys.push((depth, s));
                }
            }
            _ => {}
        }
        i += 1;
    }
    keys
}

/// # Design promise
/// AC-002-16: the JSON report is schema `scan/1` with a stable set and order of keys (the order of
/// the struct fields); changing a name or the order is a schema change that needs a new schema id.
///
/// # Scenario (Given)
/// A scan with a healthy volume, one listed snapshot, and one rule (`user-caches`) with one 4 KiB
/// file (so one `top` entry); all UTF-8 paths.
///
/// # Action (When)
/// Serialize the report with `serde_json` and list every `(depth, key)` in document order.
///
/// # Expected (Then)
/// `schema == "scan/1"` and the exact key sequence: top level `schema, run_id, home, volume{mount_point,
/// total, available, available_important, purgeable, purgeable_clamped, volume_error}, snapshots[{name,
/// date, bytes}], snapshots_unparsed, snapshots_error, rules[{id, tier, status, bytes, logical_bytes,
/// items, skipped, skipped_by_reason, vanished, deduped_links, top[{path, bytes}]}], totals{safe, caution,
/// report-only}, notes, incomplete, interrupted, audit_unavailable` (`home_b64`/`path_b64` absent for
/// UTF-8 paths).
///
/// # Must never
/// Drop a documented key, reorder keys, or emit `path_b64` for clean UTF-8 paths.
///
/// # Would catch
/// A `HashMap`-based or hand-built JSON (random order), a renamed `report-only` key, a new field
/// inserted mid-struct without a schema bump.
///
/// # Why this test (not redundant)
/// The only schema pin. Approval to change it: the orchestrator (it is a user-visible contract).
#[test]
fn ac_002_16_json_schema_scan_1_pins_key_names_and_order() {
    // Arrange
    let fs = FakeFs::builder()
        .file_sized(home("Library/Caches/x"), 4096, blocks(4096))
        .build();
    let h = harness(fs).with_runner(FakeRunner::ok(
        "Snapshots for disk /:\ncom.apple.TimeMachine.2026-11-06-123456.local\n",
    ));

    // Act
    let report = h.scan(
        &[Rule::new("user-caches", Tier::Safe, &["Library/Caches"])],
        5,
    );
    let json = serde_json::to_string(&report).expect("the report must serialize");

    // Assert
    let k = |d: usize, name: &str| (d, name.to_owned());
    let want: Vec<(usize, String)> = [
        (1, "schema"),
        (1, "run_id"),
        (1, "home"),
        (1, "volume"),
        (2, "mount_point"),
        (2, "total"),
        (2, "available"),
        (2, "available_important"),
        (2, "purgeable"),
        (2, "purgeable_clamped"),
        (2, "volume_error"),
        (1, "snapshots"),
        (3, "name"),
        (3, "date"),
        (3, "bytes"),
        (1, "snapshots_unparsed"),
        (1, "snapshots_error"),
        (1, "rules"),
        (3, "id"),
        (3, "tier"),
        (3, "status"),
        (3, "bytes"),
        (3, "logical_bytes"),
        (3, "items"),
        (3, "skipped"),
        (3, "skipped_by_reason"),
        (3, "vanished"),
        (3, "deduped_links"),
        (3, "top"),
        (5, "path"),
        (5, "bytes"),
        (1, "totals"),
        (2, "safe"),
        (2, "caution"),
        (2, "report-only"),
        (1, "notes"),
        (1, "incomplete"),
        (1, "interrupted"),
        (1, "audit_unavailable"),
    ]
    .iter()
    .map(|(d, n)| k(*d, n))
    .collect();
    assert_eq!(
        key_sequence(&json),
        want,
        "AC-002-16: the JSON key names/order are the scan/1 schema (json: {json})"
    );
    assert_eq!(report.schema, "scan/1", "the schema id");
}

/// # Design promise
/// AC-002-20: `notes` is an array of stable codes, always containing the four honesty codes
/// (purgeable is OS-managed; purgeable and reclaimable are not additive; a Trash move frees nothing
/// until emptied; clone over-count is possible), plus `snapshot_sizes_unavailable` when snapshots
/// are listed. Codes, not prose.
///
/// # Scenario (Given)
/// Two scans of an empty home: `tmutil` reporting no snapshots, and reporting one snapshot.
///
/// # Action (When)
/// `run_scan`.
///
/// # Expected (Then)
/// Row 1: exactly the four codes in spec order. Row 2: the four codes then
/// `snapshot_sizes_unavailable`.
///
/// # Must never
/// Omit a mandatory code; emit prose; reorder codes between runs.
///
/// # Would catch
/// Notes added only on some paths (e.g. only when purgeable is known), free-text notes, unstable order.
///
/// # Why this test (not redundant)
/// The only exact check of the notes list (the snapshots test only checks the optional note's wiring).
#[test]
fn ac_002_20_notes_are_the_four_stable_codes_plus_the_snapshot_code_when_listed() {
    // Arrange
    let base = [
        NOTE_PURGEABLE_OS_MANAGED,
        NOTE_NOT_ADDITIVE,
        NOTE_TRASH_FREES_NOTHING,
        NOTE_CLONE_OVERCOUNT,
    ];
    let mut with_snapshot = base.to_vec();
    with_snapshot.push(NOTE_SNAPSHOT_SIZES_UNAVAILABLE);
    let rows = [
        ("no snapshots", TMUTIL_NO_SNAPSHOTS, base.to_vec()),
        (
            "one snapshot",
            "Snapshots for disk /:\ncom.apple.TimeMachine.2026-11-06-123456.local\n",
            with_snapshot,
        ),
    ];

    for (name, stdout, want) in rows {
        let h =
            harness(FakeFs::builder().dir("/Users/u").build()).with_runner(FakeRunner::ok(stdout));

        // Act
        let report = h.scan(&[], 5);

        // Assert
        assert_eq!(report.notes, want, "{name}: AC-002-20 note codes and order");
    }
}

/// # Design promise
/// AC-002-16 / AC-001-13 / INV-16: a non-UTF-8 path in `top` is reported as lossy `path` plus
/// `path_b64` (standard padded base64 of the raw bytes); clean UTF-8 paths carry no `path_b64` key.
///
/// # Scenario (Given)
/// Rule root `Library/Caches` with two 4 KiB children: `ok` and `bad\xFF` (a name that is not UTF-8;
/// byte order puts it first).
///
/// # Action (When)
/// `run_scan` with N=5 and serialize.
///
/// # Expected (Then)
/// `top[0].path == "/Users/u/Library/Caches/bad\u{FFFD}"`, `top[0].path_b64` decodes (independent
/// `base64` oracle) to the exact raw bytes of the path; `top[1].path_b64 == None` and its JSON object
/// has no `path_b64` key.
///
/// # Must never
/// Lose the original bytes; add `path_b64` to a clean path; panic on the name.
///
/// # Would catch
/// `to_str().unwrap()`/lossy-only reporting (two different files indistinguishable), always emitting
/// `path_b64`, URL-safe/unpadded base64.
///
/// # Why this test (not redundant)
/// The only report-level path-fidelity test (the audit's own is spec 001).
#[test]
fn ac_002_16_non_utf8_paths_carry_path_b64_and_utf8_paths_do_not() {
    // Arrange
    let root = home("Library/Caches");
    let bad: PathBuf = root.join(OsString::from_vec(b"bad\xFF".to_vec()));
    let fs = FakeFs::builder()
        .file_sized(&bad, 4096, blocks(4096))
        .file_sized(root.join("ok"), 4096, blocks(4096))
        .build();
    let h = harness(fs);

    // Act
    let report = h.scan(
        &[Rule::new("user-caches", Tier::Safe, &["Library/Caches"])],
        5,
    );
    let json = serde_json::to_value(&report).expect("the report must serialize");

    // Assert
    let top = &rule_report(&report, "user-caches").top;
    assert_eq!(top.len(), 2, "both children are top entries");
    assert_eq!(
        top[0].path, "/Users/u/Library/Caches/bad\u{FFFD}",
        "lossy path of the non-UTF-8 child"
    );
    let raw = base64::engine::general_purpose::STANDARD
        .decode(top[0].path_b64.as_deref().unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(
        raw,
        std::os::unix::ffi::OsStrExt::as_bytes(bad.as_os_str()),
        "path_b64 must decode to the exact raw bytes of the path"
    );
    assert_eq!(
        top[1].path_b64, None,
        "a clean UTF-8 path carries no path_b64"
    );
    assert!(
        json["rules"][0]["top"][1].get("path_b64").is_none(),
        "the JSON of a clean path must not contain a path_b64 key"
    );
}

/// # Design promise
/// Vocabulary / AC-002-16: `totals` are per-tier sums of the rules' allocated bytes (and nothing
/// else - purgeable space is never added).
///
/// # Scenario (Given)
/// Two Safe rules (4096 + 8192), one Caution (512), one Report-only (1024); a volume with purgeable
/// space.
///
/// # Action (When)
/// `run_scan`.
///
/// # Expected (Then)
/// `totals == {safe: 12288, caution: 512, report-only: 1024}`.
///
/// # Must never
/// Mix tiers or add purgeable bytes.
///
/// # Would catch
/// Totals computed for one tier only, `Report-only` folded into `Caution`, purgeable added.
///
/// # Why this test (not redundant)
/// The only tier-aggregation test.
#[test]
fn ac_002_16_totals_are_per_tier_sums_of_rule_bytes() {
    // Arrange
    let fs = FakeFs::builder()
        .file_sized(home("s1/f"), 4096, blocks(4096))
        .file_sized(home("s2/f"), 8192, blocks(8192))
        .file_sized(home("c1/f"), 512, blocks(512))
        .file_sized(home("r1/f"), 1024, blocks(1024))
        .build();
    let h = harness(fs);
    let rules = [
        Rule::new("s1", Tier::Safe, &["s1"]),
        Rule::new("s2", Tier::Safe, &["s2"]),
        Rule::new("c1", Tier::Caution, &["c1"]),
        Rule::new("r1", Tier::ReportOnly, &["r1"]),
    ];

    // Act
    let report = h.scan(&rules, 0);

    // Assert
    let t = report.totals;
    assert_eq!(
        (t.safe, t.caution, t.report_only),
        (12_288, 512, 1024),
        "per-tier sums of rule bytes"
    );
}

/// # Design promise
/// AC-002-2 / -7 / -8 / -10 / -17 / -18 / -21 (exit code policy): `exit_code()` is 130 when
/// interrupted, else 4 when anything is partial or unknown, else 0; absent roots and vanished
/// entries never raise it.
///
/// # Scenario (Given)
/// A clean report (one rule with an absent root, healthy volume, snapshots known, audit fine) and
/// rows that change one field: rule `Partial`; rule `Refused`; `purgeable = None`; `snapshots =
/// None`; `audit_unavailable`; rule `Absent` (stays clean); `vanished = 7` (stays clean);
/// `interrupted` (130, even together with a partial rule).
///
/// # Action (When)
/// `exit_code()` on each variant.
///
/// # Expected (Then)
/// Clean/absent/vanished -> 0; partial, refused, unknown purgeable, unknown snapshots, unavailable
/// audit -> 4; interrupted -> 130 (also with partial).
///
/// # Must never
/// Exit 0 with unknown or partial data (INV-13); exit 4 for an absent root or a vanished file.
///
/// # Would catch
/// Missing triggers (e.g. forgetting the audit flag), `partial` raising 130, a status-only check that
/// ignores unknown purgeable.
///
/// # Why this test (not redundant)
/// The only test of the exit-code policy as a pure function; the scenarios that *produce* each state
/// are covered by the AC tests of the walker and volume.
#[test]
fn ac_002_exit_code_policy_130_interrupted_4_partial_or_unknown_0_otherwise() {
    // Arrange: a clean baseline report from a real (fake-backed) scan.
    let h = harness(FakeFs::builder().dir("/Users/u").build());
    let clean: ScanReport = h.scan(&[Rule::new("r", Tier::Safe, &["nowhere"])], 0);
    let variant = |f: &dyn Fn(&mut ScanReport)| {
        let mut r = clean.clone();
        f(&mut r);
        r
    };
    let rows: Vec<(&str, ScanReport, i32)> = vec![
        ("clean (absent root)", clean.clone(), 0),
        (
            "rule absent",
            variant(&|r| r.rules[0].status = RuleStatus::Absent),
            0,
        ),
        ("vanished entries", variant(&|r| r.rules[0].vanished = 7), 0),
        (
            "rule partial",
            variant(&|r| r.rules[0].status = RuleStatus::Partial),
            4,
        ),
        (
            "rule refused",
            variant(&|r| r.rules[0].status = RuleStatus::Refused),
            4,
        ),
        (
            "purgeable unknown",
            variant(&|r| r.volume.purgeable = None),
            4,
        ),
        ("snapshots unknown", variant(&|r| r.snapshots = None), 4),
        (
            "audit unavailable",
            variant(&|r| r.audit_unavailable = true),
            4,
        ),
        ("interrupted", variant(&|r| r.interrupted = true), 130),
        (
            "interrupted and partial",
            variant(&|r| {
                r.interrupted = true;
                r.rules[0].status = RuleStatus::Partial;
            }),
            130,
        ),
    ];

    for (name, report, want) in rows {
        // Act + Assert
        assert_eq!(report.exit_code(), want, "exit code for `{name}`");
    }
}
