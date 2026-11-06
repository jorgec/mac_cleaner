//! The read-only scanner (spec 002, phase 1). It sees the machine only through the read-only
//! ports in [`ScanPorts`]: there is **no mutating port** on this path (INV-01).
//!
//! # Contract summary (see `docs/specs/002-purgeable-space-scan.md` and `002a-test-matrix.md`)
//! * Roots are `home.join(rule.roots[i])`, each admitted through `SafetyGuard::admit_root`; a
//!   refused root makes the rule `Refused` and nothing below it is listed.
//! * The walk is **iterative** (no recursion; 10 000+ levels deep must not overflow the stack),
//!   never lists a symlink, never leaves the root's device, and examines directory entries in
//!   ascending byte order of their names (so results do not depend on `read_dir` order).
//! * Bytes are `blocks * 512` of regular files and symlinks, hardlinks counted once per
//!   `(dev, ino)` across the whole run (the first rule in rule order wins), saturating arithmetic.
//! * Audit: `run_start`, per rule `skipped`* and one `scan_result`, `run_end`; at most
//!   [`MAX_SKIPPED_RECORDS`] `skipped` records per run.
//! * The scan always completes and reports, whatever the audit sink does (INV-13: read-only).

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::audit::{AuditLog, Record, ScanCounts, encode_path};
use crate::cancel::CancelToken;
use crate::ports::{
    Clock, CommandRunner, FileKind, Fs, Metadata, RunId, VolumeCapacity, VolumeCaps, VolumeError,
};
use crate::report::{
    NOTE_CLONE_OVERCOUNT, NOTE_NOT_ADDITIVE, NOTE_PURGEABLE_OS_MANAGED,
    NOTE_SNAPSHOT_SIZES_UNAVAILABLE, NOTE_TRASH_FREES_NOTHING, RuleReport, RuleStatus, SCHEMA,
    SKIP_CROSS_DEVICE, SKIP_IO_ERROR, SKIP_PERMISSION_DENIED, SKIP_ROOT_REFUSED, ScanReport,
    TierTotals, TopEntry, VolumeReport,
};
use crate::rules::{Rule, Tier, owner_of};
use crate::safety::{DeniedKind, HomeDir, SafetyGuard};
use crate::snapshots::{ParsedSnapshots, SnapshotsError, list_local_snapshots};
use crate::volume::purgeable;

/// Default number of `top` children per rule.
pub const DEFAULT_TOP_N: usize = 5;
/// Cap on individually logged `skipped` audit records per run (AC-002-17).
pub const MAX_SKIPPED_RECORDS: usize = 1000;

/// The ports a scan reads through. All read-only by type.
#[derive(Clone, Copy)]
pub struct ScanPorts<'a> {
    /// Metadata and directory listing.
    pub fs: &'a dyn Fs,
    /// Source of "now" for the age filter.
    pub clock: &'a dyn Clock,
    /// Volume capacity (purgeable space).
    pub volume: &'a dyn VolumeCapacity,
    /// Runs `tmutil listlocalsnapshots /`.
    pub runner: &'a dyn CommandRunner,
}

impl std::fmt::Debug for ScanPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanPorts").finish_non_exhaustive()
    }
}

/// What to scan and how it is described in the audit log.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Injected home directory; the volume is queried at this path and rule roots hang below it.
    pub home: HomeDir,
    /// Rules to scan, already selected by the caller, in rule order.
    pub rules: Vec<Rule>,
    /// Number of `top` children to report per rule (0 allowed).
    pub top_n: usize,
    /// Command line, for the `run_start` record.
    pub argv: Vec<String>,
    /// Tool version, for the `run_start` record.
    pub version: String,
    /// Identifier of this run (must equal the one the `AuditLog` was created with).
    pub run_id: RunId,
}

/// Bytes per `st_blocks` unit (always 512 on macOS, whatever the volume's block size).
const BLOCK_BYTES: u64 = 512;

/// Run one scan.
///
/// `audit` is `None` when the audit sink could not be opened (`AuditError::Unavailable`); the scan
/// still runs and the report has `audit_unavailable == true`, as it does when a write fails
/// mid-run (writing then stops, so the log never has holes in its `seq`). `cancel` is polled
/// before every directory listing; after it is set no further directory is listed, the report has
/// `incomplete` and `interrupted` set, the unfinished and unstarted rules are `Interrupted`, and
/// `run_end` (with `interrupted: true`) is still written.
///
/// Postconditions: one `RuleReport` per `opts.rules` entry in rule order; audit records in the
/// order `run_start`, per rule its `skipped` records then one `scan_result`, `run_end` (at most
/// [`MAX_SKIPPED_RECORDS`] `skipped` records per run, the overflow counted in the rule's
/// `skipped_unlogged`); `run_end.exit_code` equals the report's exit code at that moment.
///
/// Boundaries: every root must be relative and pass `SafetyGuard::admit_root`, else its rule is
/// `Refused` with 0 bytes and nothing under it is listed (any refused root refuses the rule); a
/// root whose own `lstat` fails with `EACCES`/`EPERM` is not refused but skipped (one
/// `permission_denied` skip, never listed, the rule is `Partial` even when it has no other root); symlinks are counted as links and never
/// entered; a directory on another device than its root is not listed (`cross_device`); entries
/// are visited in ascending byte order of their names; hardlinks count once per `(dev, ino)`
/// across the run, for the first rule in rule order; a path is walked only by the rule that
/// [`owner_of`] names. Rule roots must not nest inside another root of the *same* rule (the
/// overlap would be counted twice).
///
/// Forbidden effects: any filesystem mutation (there is no mutating port in [`ScanPorts`]), any
/// command other than `tmutil listlocalsnapshots /`, reading file contents, retrying a failed
/// entry, panicking on any input.
#[must_use]
pub fn run_scan(
    ports: &ScanPorts<'_>,
    opts: &ScanOptions,
    cancel: &CancelToken,
    audit: Option<&mut AuditLog>,
) -> ScanReport {
    let mut audit = AuditWriter::new(audit);
    audit.write(&Record::RunStart {
        argv: opts.argv.clone(),
        rule_ids: opts.rules.iter().map(|r| r.id.clone()).collect(),
        version: opts.version.clone(),
        home: opts.home.path().to_path_buf(),
    });
    let volume = volume_report(ports.volume.query(opts.home.path()));
    let (snapshots, snapshots_unparsed, snapshots_error) = match list_local_snapshots(ports.runner)
    {
        Ok(ParsedSnapshots {
            snapshots,
            unparsed,
        }) => (Some(snapshots), unparsed, None),
        Err(e) => (None, 0, Some(SnapshotsError::kind(&e).to_owned())),
    };

    let mut scanner = Scanner {
        ports,
        opts,
        cancel,
        guard: SafetyGuard::new(&opts.home),
        now: ports.clock.now(),
        seen: HashSet::new(),
        skips_logged: 0,
        audit,
    };
    let rules: Vec<RuleReport> = opts
        .rules
        .iter()
        .map(|rule| scanner.scan_rule(rule))
        .collect();
    let mut audit = scanner.audit;

    let interrupted = rules.iter().any(|r| r.status == RuleStatus::Interrupted);
    let (home, home_b64) = encode_path(opts.home.path());
    let mut notes = vec![
        NOTE_PURGEABLE_OS_MANAGED.to_owned(),
        NOTE_NOT_ADDITIVE.to_owned(),
        NOTE_TRASH_FREES_NOTHING.to_owned(),
        NOTE_CLONE_OVERCOUNT.to_owned(),
    ];
    if snapshots.as_ref().is_some_and(|list| !list.is_empty()) {
        notes.push(NOTE_SNAPSHOT_SIZES_UNAVAILABLE.to_owned());
    }
    let mut report = ScanReport {
        schema: SCHEMA.to_owned(),
        run_id: opts.run_id.as_str().to_owned(),
        home,
        home_b64,
        volume,
        snapshots,
        snapshots_unparsed,
        snapshots_error,
        totals: tier_totals(&rules),
        rules,
        notes,
        incomplete: interrupted,
        interrupted,
        audit_unavailable: audit.unavailable,
    };
    audit.write(&Record::RunEnd {
        exit_code: report.exit_code(),
        interrupted,
        total_bytes: report
            .rules
            .iter()
            .fold(0, |sum, r| u64::saturating_add(sum, r.bytes)),
        total_items: report
            .rules
            .iter()
            .fold(0, |sum, r| u64::saturating_add(sum, r.items)),
    });
    report.audit_unavailable = audit.unavailable;
    report
}

/// The volume section: every number unknown (`None`) when the query failed, never zero (INV-13).
fn volume_report(queried: Result<VolumeCaps, VolumeError>) -> VolumeReport {
    match queried {
        Ok(caps) => {
            let purgeable = purgeable(&caps);
            VolumeReport {
                mount_point: Some(caps.mount_point.to_string_lossy().into_owned()),
                total: Some(caps.total),
                available: Some(caps.available),
                available_important: Some(caps.available_important),
                purgeable: Some(purgeable.bytes),
                purgeable_clamped: purgeable.clamped,
                volume_error: None,
            }
        }
        Err(e) => VolumeReport {
            mount_point: None,
            total: None,
            available: None,
            available_important: None,
            purgeable: None,
            purgeable_clamped: false,
            volume_error: Some(e.kind().to_owned()),
        },
    }
}

/// Per-tier sums of the rules' allocated bytes (saturating).
fn tier_totals(rules: &[RuleReport]) -> TierTotals {
    let mut totals = TierTotals::default();
    for rule in rules {
        let slot = match rule.tier {
            Tier::Safe => &mut totals.safe,
            Tier::Caution => &mut totals.caution,
            Tier::ReportOnly => &mut totals.report_only,
        };
        *slot = slot.saturating_add(rule.bytes);
    }
    totals
}

/// The audit log as the scan sees it: optional, and switched off for good after the first failed
/// write (a later success would leave a hole in the log).
struct AuditWriter<'a> {
    log: Option<&'a mut AuditLog>,
    unavailable: bool,
}

impl<'a> AuditWriter<'a> {
    fn new(log: Option<&'a mut AuditLog>) -> Self {
        Self {
            unavailable: log.is_none(),
            log,
        }
    }

    /// Append `record`; on failure remember that the log is unavailable and stop writing.
    fn write(&mut self, record: &Record) {
        if let Some(log) = self.log.as_mut()
            && log.record(record).is_err()
        {
            self.log = None;
            self.unavailable = true;
        }
    }
}

/// Whether the walk of a rule may go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Cancelled,
}

/// A path waiting to be examined, with the index (in [`RuleAcc::tops`]) of the immediate child of
/// the root it lies under.
struct Item {
    path: PathBuf,
    top: Option<usize>,
}

/// Running totals of one rule.
#[derive(Default)]
struct RuleAcc {
    bytes: u64,
    logical_bytes: u64,
    items: u64,
    skipped: u64,
    skipped_unlogged: u64,
    skipped_by_reason: BTreeMap<String, u64>,
    vanished: u64,
    deduped_links: u64,
    /// An entry could not be examined for a reason other than `cross_device`.
    partial: bool,
    /// Immediate children of the roots with the bytes counted under each.
    tops: Vec<(PathBuf, u64)>,
}

/// State shared by all rules of one run.
struct Scanner<'a> {
    ports: &'a ScanPorts<'a>,
    opts: &'a ScanOptions,
    cancel: &'a CancelToken,
    guard: SafetyGuard,
    now: SystemTime,
    /// `(dev, ino)` of every multi-linked inode counted so far in the run.
    seen: HashSet<(u64, u64)>,
    /// `skipped` records written (or due) so far in the run, against [`MAX_SKIPPED_RECORDS`].
    skips_logged: usize,
    audit: AuditWriter<'a>,
}

/// Verdict on one rule root.
enum Admission {
    /// Absolute path of an admitted root that exists.
    Present(PathBuf),
    /// Admitted but not there (not an error, AC-002-10).
    Absent,
    /// Admitted by the guard's lexical checks, but `lstat` of the root itself failed with
    /// `EACCES`/`EPERM` (e.g. a TCC-protected root): skipped, not refused (INV-09).
    PermissionDenied(PathBuf),
    /// Not relative, or refused by a guard verdict or another I/O error; the path as it was tried.
    Refused(PathBuf),
}

impl Scanner<'_> {
    /// Scan `rule` (an element of `opts.rules`) and write its `scan_result` record.
    fn scan_rule(&mut self, rule: &Rule) -> RuleReport {
        let mut acc = RuleAcc::default();
        let status = self.walk_rule(rule, &mut acc);
        let report = RuleReport {
            id: rule.id.clone(),
            tier: rule.tier,
            status,
            bytes: acc.bytes,
            logical_bytes: acc.logical_bytes,
            items: acc.items,
            skipped: acc.skipped,
            skipped_by_reason: acc.skipped_by_reason,
            vanished: acc.vanished,
            deduped_links: acc.deduped_links,
            top: top_entries(acc.tops, self.opts.top_n),
        };
        self.audit.write(&Record::ScanResult {
            rule_id: report.id.clone(),
            status: status.as_str().to_owned(),
            bytes: report.bytes,
            items: report.items,
            counts: ScanCounts {
                logical_bytes: report.logical_bytes,
                skipped: report.skipped,
                skipped_unlogged: acc.skipped_unlogged,
                vanished: report.vanished,
                deduped_links: report.deduped_links,
            },
        });
        report
    }

    /// Admit the roots of `rule` and walk them; the rule's final status.
    fn walk_rule(&mut self, rule: &Rule, acc: &mut RuleAcc) -> RuleStatus {
        if self.cancel.is_cancelled() {
            return RuleStatus::Interrupted;
        }
        let mut roots = Vec::new();
        let mut refused = false;
        for rel in &rule.roots {
            match self.admit_root(rel) {
                Admission::Refused(path) => {
                    refused = true;
                    self.skip(acc, &path, SKIP_ROOT_REFUSED);
                }
                Admission::PermissionDenied(path) => {
                    acc.partial = true;
                    self.skip(acc, &path, SKIP_PERMISSION_DENIED);
                }
                Admission::Absent => {}
                Admission::Present(path) => roots.push(path),
            }
        }
        if refused {
            return RuleStatus::Refused;
        }
        if roots.is_empty() {
            return if acc.partial {
                RuleStatus::Partial
            } else {
                RuleStatus::Absent
            };
        }
        for root in &roots {
            if self.walk_root(rule, root, acc) == Flow::Cancelled {
                return RuleStatus::Interrupted;
            }
        }
        if acc.partial {
            RuleStatus::Partial
        } else {
            RuleStatus::Ok
        }
    }

    /// Resolve a rule root against the home directory and ask the guard. A root that is not
    /// relative is refused without being resolved (`Path::join` would let it escape `$HOME`).
    ///
    /// The guard reports every `lstat` failure of the root as `DeniedKind::Io` without the errno;
    /// for that verdict only, the root is `lstat`ed once more to tell a permission error (the root
    /// is protected: a skip) from any other failure (fail closed: refused).
    fn admit_root(&self, rel: &Path) -> Admission {
        if !rel.is_relative() {
            return Admission::Refused(rel.to_path_buf());
        }
        let abs = self.opts.home.path().join(rel);
        match self.guard.admit_root(self.ports.fs, &abs) {
            Ok(safe) if safe.exists() => Admission::Present(abs),
            Ok(_) => Admission::Absent,
            Err(denied)
                if denied.kind == DeniedKind::Io
                    && self
                        .ports
                        .fs
                        .lstat(&abs)
                        .is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied) =>
            {
                Admission::PermissionDenied(abs)
            }
            Err(_) => Admission::Refused(abs),
        }
    }

    /// Walk one admitted root iteratively, depth first, entries in ascending name order.
    fn walk_root(&mut self, rule: &Rule, root: &Path, acc: &mut RuleAcc) -> Flow {
        let root_meta = match self.ports.fs.lstat(root) {
            Ok(meta) => meta,
            Err(e) => {
                self.record_error(acc, root, &e);
                return Flow::Continue;
            }
        };
        if root_meta.kind != FileKind::Dir {
            self.count(rule, &root_meta, None, acc);
            return Flow::Continue;
        }
        let mut stack = Vec::new();
        if self.list_into(rule, root, None, &mut stack, acc) == Flow::Cancelled {
            return Flow::Cancelled;
        }
        while let Some(item) = stack.pop() {
            let meta = match self.ports.fs.lstat(&item.path) {
                Ok(meta) => meta,
                Err(e) => {
                    self.record_error(acc, &item.path, &e);
                    continue;
                }
            };
            match meta.kind {
                FileKind::Dir if meta.dev != root_meta.dev => {
                    self.skip(acc, &item.path, SKIP_CROSS_DEVICE);
                }
                FileKind::Dir => {
                    if self.list_into(rule, &item.path, item.top, &mut stack, acc)
                        == Flow::Cancelled
                    {
                        return Flow::Cancelled;
                    }
                }
                FileKind::File | FileKind::Symlink => self.count(rule, &meta, item.top, acc),
                FileKind::Other => {}
            }
        }
        Flow::Continue
    }

    /// List `dir` (polling the cancel token first) and push the entries that `rule` claims onto
    /// `stack` so that they pop in ascending name order. `top` is the immediate child of the root
    /// the entries lie under; `None` means `dir` is the root, whose children each start a new
    /// `top` slot.
    fn list_into(
        &mut self,
        rule: &Rule,
        dir: &Path,
        top: Option<usize>,
        stack: &mut Vec<Item>,
        acc: &mut RuleAcc,
    ) -> Flow {
        if self.cancel.is_cancelled() {
            return Flow::Cancelled;
        }
        let mut entries = match self.ports.fs.read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                self.record_error(acc, dir, &e);
                return Flow::Continue;
            }
        };
        entries.sort_unstable_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for entry in entries.into_iter().rev() {
            let path = dir.join(&entry.name);
            if !self.claims(rule, &path) {
                continue;
            }
            let top = top.or_else(|| {
                acc.tops.push((path.clone(), 0));
                acc.tops.len().checked_sub(1)
            });
            stack.push(Item { path, top });
        }
        Flow::Continue
    }

    /// True when `rule` is the rule that owns `path` (most specific root, not excluded).
    fn claims(&self, rule: &Rule, path: &Path) -> bool {
        path.strip_prefix(self.opts.home.path())
            .ok()
            .and_then(|rel| owner_of(&self.opts.rules, rel))
            .is_some_and(|owner| std::ptr::eq(owner, rule))
    }

    /// Count a regular file or symlink for `rule`: age filter, hardlink dedupe, saturating sums.
    fn count(&mut self, rule: &Rule, meta: &Metadata, top: Option<usize>, acc: &mut RuleAcc) {
        if let Some(min_age) = rule.min_age {
            let old_enough = meta.kind == FileKind::File
                && self
                    .now
                    .checked_sub(min_age)
                    .is_some_and(|cutoff| meta.mtime <= cutoff);
            if !old_enough {
                return;
            }
        }
        if meta.nlink > 1 && !self.seen.insert((meta.dev, meta.ino)) {
            acc.deduped_links += 1;
            return;
        }
        let bytes = meta.blocks.saturating_mul(BLOCK_BYTES);
        acc.bytes = acc.bytes.saturating_add(bytes);
        acc.logical_bytes = acc.logical_bytes.saturating_add(meta.len);
        acc.items += 1;
        if let Some(slot) = top.and_then(|index| acc.tops.get_mut(index)) {
            slot.1 = slot.1.saturating_add(bytes);
        }
    }

    /// Classify a failed `lstat` or listing of `path`: `ENOENT` is a vanished entry; everything
    /// else is a skip that makes the rule partial. One attempt only: no retry (INV-09, INV-10).
    fn record_error(&mut self, acc: &mut RuleAcc, path: &Path, error: &io::Error) {
        match error.kind() {
            io::ErrorKind::NotFound => acc.vanished += 1,
            io::ErrorKind::PermissionDenied => {
                acc.partial = true;
                self.skip(acc, path, SKIP_PERMISSION_DENIED);
            }
            _ => {
                acc.partial = true;
                self.skip(acc, path, SKIP_IO_ERROR);
            }
        }
    }

    /// Tally a skipped entry and write its `skipped` record unless the per-run cap is reached.
    fn skip(&mut self, acc: &mut RuleAcc, path: &Path, reason: &str) {
        acc.skipped += 1;
        *acc.skipped_by_reason.entry(reason.to_owned()).or_default() += 1;
        if self.skips_logged < MAX_SKIPPED_RECORDS {
            self.skips_logged += 1;
            self.audit.write(&Record::Skipped {
                path: path.to_path_buf(),
                reason: reason.to_owned(),
            });
        } else {
            acc.skipped_unlogged += 1;
        }
    }
}

/// The `n` largest immediate children (bytes descending, then path bytes ascending), without
/// children that contributed nothing.
fn top_entries(mut tops: Vec<(PathBuf, u64)>, n: usize) -> Vec<TopEntry> {
    tops.retain(|(_, bytes)| *bytes > 0);
    tops.sort_unstable_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.as_os_str().as_bytes().cmp(b.0.as_os_str().as_bytes()))
    });
    tops.truncate(n);
    tops.into_iter()
        .map(|(path, bytes)| {
            let (path, path_b64) = encode_path(&path);
            TopEntry {
                path,
                path_b64,
                bytes,
            }
        })
        .collect()
}
