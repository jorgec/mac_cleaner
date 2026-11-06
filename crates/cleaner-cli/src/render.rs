//! Rendering of a [`ScanReport`] for people (AC-002-16, AC-002-7 hint). Pure functions; the JSON
//! form is `serde_json` over the report model and needs no code here.

use std::fmt::Write as _;
use std::path::PathBuf;

use cleaner_core::report::{RuleReport, RuleStatus, SKIP_PERMISSION_DENIED, ScanReport};
use cleaner_core::rules::Tier;

/// Everything the human report shows that is not in the [`ScanReport`].
#[derive(Debug, Clone)]
pub struct HumanContext {
    /// Path of the audit log file of this run; `None` when the log was unavailable.
    pub audit_log: Option<PathBuf>,
    /// Name of the terminal app for the Full Disk Access hint ([`crate::fda::terminal_app`]).
    pub terminal_app: String,
}

/// Units above bytes, each 1000 times the previous.
const UNITS: [&str; 6] = ["kB", "MB", "GB", "TB", "PB", "EB"];

/// Bytes in base-10 units with one decimal: `B` (integer, no decimal), `kB`, `MB`, `GB`, `TB`,
/// `PB`, `EB`; the unit is the largest one for which the **rounded** value is below 1000 (so
/// 999 950 bytes is `1.0 MB`, never `1000.0 kB`); the whole `u64` range is supported.
///
/// Examples: `0` -> `0 B`; `999` -> `999 B`; `1000` -> `1.0 kB`; `4_193_357_792` -> `4.2 GB`;
/// `494_384_795_648` -> `494.4 GB`; `u64::MAX` -> `18.4 EB`. Pure.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut shown = format!("{bytes} B");
    for (unit, power) in UNITS.iter().zip(1_u32..) {
        // Tenths of the unit, rounded half up.
        let divisor = 1000_u128.pow(power);
        let tenths = (u128::from(bytes) * 10 + divisor / 2) / divisor;
        shown = format!("{}.{} {unit}", tenths / 10, tenths % 10);
        if tenths < 10_000 {
            break;
        }
    }
    shown
}

/// True when the rule skipped at least one entry because the OS denied access.
fn has_permission_problem(rule: &RuleReport) -> bool {
    rule.skipped_by_reason
        .get(SKIP_PERMISSION_DENIED)
        .is_some_and(|n| *n > 0)
}

/// The one-line Full Disk Access hint when any rule skipped an entry with reason
/// `permission_denied`, else `None` (other skip reasons never trigger it). The line names the
/// *terminal app* (not the binary) and contains the words `Full Disk Access`. One line per
/// report: two denied rules still give one hint. Pure.
#[must_use]
pub fn permission_hint(report: &ScanReport, terminal_app: &str) -> Option<String> {
    report.rules.iter().any(has_permission_problem).then(|| {
        format!(
            "Some entries could not be read: grant Full Disk Access to {terminal_app} \
                 (System Settings > Privacy & Security) and scan again."
        )
    })
}

/// The tier line: label, tier total, and the contributing rules.
fn tier_line(report: &ScanReport, label: &str, tier: Tier, total: u64) -> String {
    let rules: Vec<String> = report
        .rules
        .iter()
        .filter(|r| r.tier == tier)
        .filter_map(|r| {
            let denied = has_permission_problem(r);
            (r.bytes > 0 || denied).then(|| {
                let mut entry = format!("{} {}", r.id, format_bytes(r.bytes));
                if denied {
                    entry.push_str(" (permission denied)");
                }
                entry
            })
        })
        .collect();
    let mut line = format!("  {label:<12}  {:>10}", format_bytes(total));
    if !rules.is_empty() {
        let _ = write!(line, "   {}", rules.join(" \u{b7} "));
    }
    line
}

/// One line per rule whose status is `refused`, `partial` or `interrupted`, whatever its bytes:
/// `<rule-id>: <status>` followed by its skip reason codes (`code xN`, sorted) when it has any.
fn problem_lines(report: &ScanReport) -> Vec<String> {
    report
        .rules
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                RuleStatus::Refused | RuleStatus::Partial | RuleStatus::Interrupted
            )
        })
        .map(|r| {
            let mut line = format!("  {}: {}", r.id, r.status.as_str());
            if !r.skipped_by_reason.is_empty() {
                let reasons: Vec<String> = r
                    .skipped_by_reason
                    .iter()
                    .map(|(code, n)| format!("{code} x{n}"))
                    .collect();
                let _ = write!(line, " ({})", reasons.join(", "));
            }
            line
        })
        .collect()
}

/// The human report (the stdout of `cleaner scan` without `--json`). No ANSI escape sequences.
///
/// Layout contract (the example in spec 002 "CLI surface"; tests pin tokens, not spacing):
/// * a line starting `Volume ` with the mount point, `total <bytes>` and `available <bytes>`;
/// * a line starting `Purgeable` that mentions `macOS` and `not added`, with the purgeable size, or
///   - when the volume query failed - the word `unknown` and **no digit at all** (never `0 B`);
/// * `Local snapshots: <n>` (or `unknown` when `snapshots` is `None`);
/// * a heading saying the scan is read-only and `nothing selected`, then one line per tier
///   starting (after indentation) with `Safe`, `Caution`, `Report-only`, the tier total, and
///   `<rule-id> <bytes>` for every rule of that tier with bytes > 0 (a rule that had a permission
///   problem is listed with the words `permission denied`; `ok`/`absent` rules with 0 bytes are in
///   no tier line);
/// * after the tier lines, one line per rule whose status is `refused`, `partial` or `interrupted`
///   (whatever its bytes, INV-13: a failed rule is never invisible), starting
///   `<rule-id>: <status>` and followed by its skip reason codes when it has any; `ok`/`absent`
///   rules never get such a line;
/// * the Full Disk Access hint exactly once when [`permission_hint`] is `Some`;
/// * the word `incomplete` when `report.interrupted`;
/// * `Audit log: <path>  (run <run_id>)`, or a line saying the log is unavailable.
///
/// It never contains the words `recommend`/`recommended` and never says `selected` except in
/// `nothing selected` (INV-02). Pure.
#[must_use]
pub fn human(report: &ScanReport, ctx: &HumanContext) -> String {
    let volume = &report.volume;
    let mut out = String::new();
    let _ = match (&volume.mount_point, volume.total, volume.available) {
        (Some(mount), Some(total), Some(available)) => writeln!(
            out,
            "Volume {mount}   total {}   available {}",
            format_bytes(total),
            format_bytes(available)
        ),
        _ => writeln!(out, "Volume unknown"),
    };
    let purgeable = volume
        .purgeable
        .map_or_else(|| "unknown".to_owned(), format_bytes);
    let _ = writeln!(
        out,
        "Purgeable (managed by macOS)   {purgeable}   [not added to the totals below]"
    );
    let snapshots = report
        .snapshots
        .as_ref()
        .map_or_else(|| "unknown".to_owned(), |list| list.len().to_string());
    let _ = writeln!(out, "Local snapshots: {snapshots}");
    let _ = writeln!(
        out,
        "Reclaimable by this tool (read-only scan; nothing selected)"
    );
    let totals = &report.totals;
    for (label, tier, total) in [
        ("Safe", Tier::Safe, totals.safe),
        ("Caution", Tier::Caution, totals.caution),
        ("Report-only", Tier::ReportOnly, totals.report_only),
    ] {
        let _ = writeln!(out, "{}", tier_line(report, label, tier, total));
    }
    for line in problem_lines(report) {
        let _ = writeln!(out, "{line}");
    }
    if let Some(hint) = permission_hint(report, &ctx.terminal_app) {
        let _ = writeln!(out, "{hint}");
    }
    if report.interrupted {
        let _ = writeln!(out, "Scan interrupted: the results above are incomplete.");
    }
    let log = ctx
        .audit_log
        .as_ref()
        .map_or_else(|| "unavailable".to_owned(), |p| p.display().to_string());
    let _ = writeln!(out, "Audit log: {log}  (run {})", report.run_id);
    out
}
