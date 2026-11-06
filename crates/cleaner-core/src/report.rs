//! The `scan/1` report model (spec 002 AC-002-2, -3, -16, -20). Field **declaration order is the
//! JSON key order** (serde derives preserve it); changing it is a schema change.
//!
//! Unknown values are `None` (JSON `null`), never `0` (INV-13): `purgeable`, `snapshots`, and the
//! volume numbers are `Option`s.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::rules::Tier;
use crate::snapshots::Snapshot;

/// Value of `schema` in this version.
pub const SCHEMA: &str = "scan/1";

/// Note code: purgeable space is managed by macOS, not by this tool.
pub const NOTE_PURGEABLE_OS_MANAGED: &str = "purgeable_is_os_managed";
/// Note code: purgeable and reclaimable numbers overlap and must not be added.
pub const NOTE_NOT_ADDITIVE: &str = "purgeable_and_reclaimable_not_additive";
/// Note code: moving to the Trash frees nothing until the Trash is emptied.
pub const NOTE_TRASH_FREES_NOTHING: &str = "trash_move_frees_nothing_until_emptied";
/// Note code: APFS clones are not detected, so sizes may over-count.
pub const NOTE_CLONE_OVERCOUNT: &str = "clone_overcount_possible";
/// Note code: snapshots are listed but `tmutil` reports no sizes.
pub const NOTE_SNAPSHOT_SIZES_UNAVAILABLE: &str = "snapshot_sizes_unavailable";

/// Skip reason: `EPERM`/`EACCES` (INV-09).
pub const SKIP_PERMISSION_DENIED: &str = "permission_denied";
/// Skip reason: a directory on another device than its root (INV-08).
pub const SKIP_CROSS_DEVICE: &str = "cross_device";
/// Skip reason: any other I/O error while listing or `lstat`ing an entry.
pub const SKIP_IO_ERROR: &str = "io_error";
/// Skip reason: the rule root itself was refused by the `SafetyGuard` (symlinked, denied, ...).
pub const SKIP_ROOT_REFUSED: &str = "root_refused";

/// Exit code of a cancelled scan (128 + SIGINT).
const EXIT_INTERRUPTED: i32 = 130;
/// Exit code of a scan with partial or unknown results.
const EXIT_PARTIAL: i32 = 4;

/// Outcome of scanning one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    /// Every entry under the roots was examined.
    Ok,
    /// Some entries could not be examined (permission denied, other I/O error, ...).
    Partial,
    /// None of the rule's roots exists (not an error).
    Absent,
    /// A root was refused by the `SafetyGuard`; nothing was scanned.
    Refused,
    /// The scan was cancelled before or while this rule was walked.
    Interrupted,
}

impl RuleStatus {
    /// The stable lowercase code written to the JSON report and the audit log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Partial => "partial",
            Self::Absent => "absent",
            Self::Refused => "refused",
            Self::Interrupted => "interrupted",
        }
    }
}

/// Volume section. `None` fields are unknown (the query failed): `volume_error` says why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeReport {
    /// Mount point of the volume holding `$HOME`.
    pub mount_point: Option<String>,
    /// Total capacity in bytes.
    pub total: Option<u64>,
    /// `volumeAvailableCapacity` in bytes.
    pub available: Option<u64>,
    /// `volumeAvailableCapacityForImportantUsage` in bytes.
    pub available_important: Option<u64>,
    /// Purgeable bytes (OS-managed), or `None` when unknown.
    pub purgeable: Option<u64>,
    /// True when the raw difference was clamped (see [`crate::volume::Purgeable::clamped`]).
    pub purgeable_clamped: bool,
    /// Stable code of the volume query failure ([`crate::ports::VolumeError::kind`]), else `None`.
    pub volume_error: Option<String>,
}

/// One of the largest immediate children of a rule's roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopEntry {
    /// Absolute path, lossy UTF-8.
    pub path: String,
    /// Standard padded base64 of the raw path bytes; present only when `path` is lossy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_b64: Option<String>,
    /// Allocated bytes counted under this child (after hardlink dedup and claims).
    pub bytes: u64,
}

/// Result for one rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleReport {
    /// Rule id.
    pub id: String,
    /// Rule tier.
    pub tier: Tier,
    /// Outcome.
    pub status: RuleStatus,
    /// Allocated bytes (`blocks * 512`), saturating.
    pub bytes: u64,
    /// Logical bytes (`len`), saturating.
    pub logical_bytes: u64,
    /// Counted regular files and symlinks.
    pub items: u64,
    /// Entries skipped (all, logged or not).
    pub skipped: u64,
    /// `skipped` broken down by reason code (sorted by code in JSON).
    pub skipped_by_reason: BTreeMap<String, u64>,
    /// Entries that vanished between listing and `lstat`.
    pub vanished: u64,
    /// Hardlink sightings after the first (counted once overall).
    pub deduped_links: u64,
    /// Up to `top_n` largest immediate children of the roots.
    pub top: Vec<TopEntry>,
}

/// Allocated bytes per tier (sums of the rules' `bytes`, saturating). Purgeable space is never
/// part of these numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TierTotals {
    /// `Safe` rules.
    pub safe: u64,
    /// `Caution` rules.
    pub caution: u64,
    /// `Report-only` rules.
    #[serde(rename = "report-only")]
    pub report_only: u64,
}

/// The complete result of one scan (JSON schema `scan/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// Run identifier (same as in the audit log).
    pub run_id: String,
    /// The injected home directory, lossy UTF-8.
    pub home: String,
    /// Raw-bytes base64 of the home, only when `home` is lossy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_b64: Option<String>,
    /// Volume capacity and purgeable space.
    pub volume: VolumeReport,
    /// Local Time Machine snapshots; `None` = unknown (see `snapshots_error`), `Some([])` = none.
    pub snapshots: Option<Vec<Snapshot>>,
    /// Lines of `tmutil` output that were not recognized snapshot names.
    pub snapshots_unparsed: u64,
    /// Stable code of the `tmutil` failure ([`crate::snapshots::SnapshotsError::kind`]), else `None`.
    pub snapshots_error: Option<String>,
    /// One entry per scanned rule, in rule order.
    pub rules: Vec<RuleReport>,
    /// Per-tier allocated bytes.
    pub totals: TierTotals,
    /// Stable honesty codes (`NOTE_*`), in a stable order.
    pub notes: Vec<String>,
    /// True when the scan did not examine everything it was asked to (cancelled).
    pub incomplete: bool,
    /// True when the user cancelled the scan.
    pub interrupted: bool,
    /// True when the audit log could not be opened or written during the run.
    pub audit_unavailable: bool,
}

impl ScanReport {
    /// The process exit code this report maps to: `130` when `interrupted`; else `4` when
    /// anything is partial or unknown (a rule `Partial`, `Refused` or `Interrupted`, an unknown
    /// purgeable value, an unknown snapshot list, an unavailable audit log); else `0`. An `Absent`
    /// rule is not a problem (AC-002-10) and neither is a `vanished` entry (AC-002-8); a
    /// `cross_device` skip alone does not change the code either (it does not make a rule
    /// `Partial`). Pure.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.interrupted {
            return EXIT_INTERRUPTED;
        }
        let incomplete_rule = self.rules.iter().any(|r| {
            matches!(
                r.status,
                RuleStatus::Partial | RuleStatus::Refused | RuleStatus::Interrupted
            )
        });
        if incomplete_rule
            || self.volume.purgeable.is_none()
            || self.snapshots.is_none()
            || self.audit_unavailable
        {
            EXIT_PARTIAL
        } else {
            0
        }
    }
}
