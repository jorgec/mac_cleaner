//! Audit log: record model, JSONL encoding, sink port, file naming and retention (INV-11, INV-13,
//! INV-16; spec 001 AC-001-11 .. AC-001-14). The file-backed sink lives in `cleaner-macos`.
//!
//! # Wire contract
//! One JSON object per line: `schema` (1), `ts` (RFC 3339 UTC, whole seconds, `Z` suffix, from the
//! injected clock; instants before the epoch clamp to `1970-01-01T00:00:00Z`), `run_id`, `seq`
//! (1-based, +1 per record, per [`AuditLog`]), `kind` (`run_start` | `scan_result` | `skipped` |
//! `run_end`), then the variant's fields. Every path field is written as `path` (lossy UTF-8)
//! plus, only when lossy != original, `path_b64` (standard base64 **with padding** of the raw
//! bytes); the `run_start` home is the same pair under `home` / `home_b64`. The line never contains
//! a raw newline.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::ports::{Clock, LogStore, RunId};

/// Value of the `schema` field written by this version.
const SCHEMA_VERSION: u32 = 1;
const SECS_PER_DAY: i64 = 86_400;

/// Per-rule counters carried by a `scan_result` record (spec 002 AC-002-17).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanCounts {
    /// Sum of logical lengths (`st_size`) of the counted entries.
    pub logical_bytes: u64,
    /// Entries of this rule that were skipped (all of them, logged or not).
    pub skipped: u64,
    /// Of `skipped`, how many were **not** written as individual `skipped` records because the
    /// per-run cap (1000) was already reached.
    pub skipped_unlogged: u64,
    /// Entries listed but gone by the time they were examined (`ENOENT`).
    pub vanished: u64,
    /// Second and later sightings of an already counted `(dev, ino)`.
    pub deduped_links: u64,
}

/// Phase-1 audit records. Reserved phase-2 variants (`plan`, `confirm`, `intent`, `outcome`) are
/// added later. Spec 002 may add fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// First record of a run.
    RunStart {
        /// Command line.
        argv: Vec<String>,
        /// Rules in scope.
        rule_ids: Vec<String>,
        /// Tool version.
        version: String,
        /// Injected home directory.
        home: PathBuf,
    },
    /// Result of scanning one rule.
    ScanResult {
        /// Rule id.
        rule_id: String,
        /// Status code (e.g. `ok`, `partial`, `absent`).
        status: String,
        /// Allocated bytes.
        bytes: u64,
        /// Item count.
        items: u64,
        /// Logical size and the skipped / vanished / deduplicated counters.
        counts: ScanCounts,
    },
    /// An entry that was not examined or touched, and why.
    Skipped {
        /// The entry.
        path: PathBuf,
        /// Stable reason code.
        reason: String,
    },
    /// Last record of a run.
    RunEnd {
        /// Process exit code.
        exit_code: i32,
        /// True when stopped by the user.
        interrupted: bool,
        /// Sum of allocated bytes over all rules of the run (never includes purgeable space).
        total_bytes: u64,
        /// Sum of items over all rules of the run.
        total_items: u64,
    },
}

/// A line read back from the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    /// `schema` field.
    pub schema: u32,
    /// `ts` field, verbatim.
    pub ts: String,
    /// `run_id` field, verbatim.
    pub run_id: String,
    /// `seq` field.
    pub seq: u64,
    /// The typed record (paths reconstructed losslessly from `path_b64` when present).
    pub record: Record,
}

/// Audit failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// The log directory/file could not be created or opened.
    #[error("audit log unavailable: {reason}")]
    Unavailable {
        /// Human-readable cause.
        reason: String,
    },
    /// Writing, flushing or listing/removing failed after the sink was open.
    #[error("audit log I/O failed: {reason}")]
    Io {
        /// Human-readable cause.
        reason: String,
    },
    /// A line could not be decoded.
    #[error("audit line could not be decoded: {reason}")]
    Decode {
        /// Human-readable cause.
        reason: String,
    },
}

/// Port: durable, append-only line storage. An implementation appends `line` plus `\n` and
/// flushes it to the OS **before returning** (AC-001-12). It never truncates.
pub trait AuditSink: Send {
    /// Append one complete JSON line (no trailing newline in `line`).
    ///
    /// # Errors
    /// [`AuditError::Io`] when the line is not durably handed to the OS.
    fn write_line(&mut self, line: &str) -> Result<(), AuditError>;
}

/// Stamps records with `schema`/`ts`/`run_id`/`seq` and hands one JSON line each to the sink.
pub struct AuditLog {
    sink: Box<dyn AuditSink>,
    clock: Arc<dyn Clock>,
    run_id: RunId,
    next_seq: u64,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("run_id", &self.run_id)
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Start a log for one run; `seq` begins at 1.
    #[must_use]
    pub fn new(sink: Box<dyn AuditSink>, clock: Arc<dyn Clock>, run_id: RunId) -> Self {
        Self {
            sink,
            clock,
            run_id,
            next_seq: 1,
        }
    }

    /// Encode `record` as one JSON line (see the module wire contract), stamped with the clock's
    /// current instant and the next `seq`, and append it through the sink. `seq` advances only
    /// for records the sink accepted, so the written log has no gaps (AC-001-11).
    ///
    /// # Errors
    /// Whatever the sink returns (the record is then not written and `seq` is unchanged), or
    /// [`AuditError::Io`] if encoding fails.
    pub fn record(&mut self, record: &Record) -> Result<(), AuditError> {
        let line = serde_json::to_string(&WireLine {
            schema: SCHEMA_VERSION,
            ts: format_ts(self.clock.now()),
            run_id: self.run_id.as_str().to_owned(),
            seq: self.next_seq,
            body: WireBody::from(record),
        })
        .map_err(|e| AuditError::Io {
            reason: format!("encoding audit record failed: {e}"),
        })?;
        self.sink.write_line(&line)?;
        self.next_seq += 1;
        Ok(())
    }
}

/// On-disk shape of one line: the envelope plus the variant's fields, tagged by `kind`.
/// Unknown fields are ignored on read (serde's default), which is the forward-compat promise.
#[derive(Serialize, Deserialize)]
struct WireLine {
    schema: u32,
    ts: String,
    run_id: String,
    seq: u64,
    #[serde(flatten)]
    body: WireBody,
}

/// The variant-specific fields, tagged by `kind`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireBody {
    RunStart {
        argv: Vec<String>,
        rule_ids: Vec<String>,
        version: String,
        home: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        home_b64: Option<String>,
    },
    ScanResult {
        rule_id: String,
        status: String,
        bytes: u64,
        items: u64,
        #[serde(default)]
        logical_bytes: u64,
        #[serde(default)]
        skipped: u64,
        #[serde(default)]
        skipped_unlogged: u64,
        #[serde(default)]
        vanished: u64,
        #[serde(default)]
        deduped_links: u64,
    },
    Skipped {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_b64: Option<String>,
        reason: String,
    },
    RunEnd {
        exit_code: i32,
        interrupted: bool,
        #[serde(default)]
        total_bytes: u64,
        #[serde(default)]
        total_items: u64,
    },
}

/// Lossy text of `path` and, when the text differs from the original bytes, their base64.
pub(crate) fn encode_path(path: &Path) -> (String, Option<String>) {
    let lossy = path.to_string_lossy();
    let b64 = (lossy.as_bytes() != path.as_os_str().as_bytes())
        .then(|| BASE64.encode(path.as_os_str().as_bytes()));
    (lossy.into_owned(), b64)
}

/// Inverse of [`encode_path`]: the exact original path, preferring the raw bytes when present.
fn decode_path(text: String, b64: Option<String>) -> Result<PathBuf, AuditError> {
    match b64 {
        None => Ok(PathBuf::from(text)),
        Some(b64) => BASE64
            .decode(b64)
            .map(|bytes| PathBuf::from(OsString::from_vec(bytes)))
            .map_err(|e| AuditError::Decode {
                reason: format!("invalid base64 path: {e}"),
            }),
    }
}

impl From<&Record> for WireBody {
    fn from(record: &Record) -> Self {
        match record {
            Record::RunStart {
                argv,
                rule_ids,
                version,
                home,
            } => {
                let (home, home_b64) = encode_path(home);
                Self::RunStart {
                    argv: argv.clone(),
                    rule_ids: rule_ids.clone(),
                    version: version.clone(),
                    home,
                    home_b64,
                }
            }
            Record::ScanResult {
                rule_id,
                status,
                bytes,
                items,
                counts,
            } => Self::ScanResult {
                rule_id: rule_id.clone(),
                status: status.clone(),
                bytes: *bytes,
                items: *items,
                logical_bytes: counts.logical_bytes,
                skipped: counts.skipped,
                skipped_unlogged: counts.skipped_unlogged,
                vanished: counts.vanished,
                deduped_links: counts.deduped_links,
            },
            Record::Skipped { path, reason } => {
                let (path, path_b64) = encode_path(path);
                Self::Skipped {
                    path,
                    path_b64,
                    reason: reason.clone(),
                }
            }
            Record::RunEnd {
                exit_code,
                interrupted,
                total_bytes,
                total_items,
            } => Self::RunEnd {
                exit_code: *exit_code,
                interrupted: *interrupted,
                total_bytes: *total_bytes,
                total_items: *total_items,
            },
        }
    }
}

/// Parse one audit line. Unknown extra fields are ignored (forward compatibility).
///
/// # Errors
/// [`AuditError::Decode`] for invalid JSON or missing/ill-typed known fields.
pub fn decode_line(line: &str) -> Result<DecodedRecord, AuditError> {
    let wire: WireLine = serde_json::from_str(line).map_err(|e| AuditError::Decode {
        reason: e.to_string(),
    })?;
    let record = match wire.body {
        WireBody::RunStart {
            argv,
            rule_ids,
            version,
            home,
            home_b64,
        } => Record::RunStart {
            argv,
            rule_ids,
            version,
            home: decode_path(home, home_b64)?,
        },
        WireBody::ScanResult {
            rule_id,
            status,
            bytes,
            items,
            logical_bytes,
            skipped,
            skipped_unlogged,
            vanished,
            deduped_links,
        } => Record::ScanResult {
            rule_id,
            status,
            bytes,
            items,
            counts: ScanCounts {
                logical_bytes,
                skipped,
                skipped_unlogged,
                vanished,
                deduped_links,
            },
        },
        WireBody::Skipped {
            path,
            path_b64,
            reason,
        } => Record::Skipped {
            path: decode_path(path, path_b64)?,
            reason,
        },
        WireBody::RunEnd {
            exit_code,
            interrupted,
            total_bytes,
            total_items,
        } => Record::RunEnd {
            exit_code,
            interrupted,
            total_bytes,
            total_items,
        },
    };
    Ok(DecodedRecord {
        schema: wire.schema,
        ts: wire.ts,
        run_id: wire.run_id,
        seq: wire.seq,
        record,
    })
}

/// Whole seconds since the Unix epoch; instants before the epoch clamp to 0 and instants beyond
/// `i64` seconds saturate (never panics).
fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Days since 1970-01-01 of a proleptic Gregorian civil date (H. Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`]: `(year, month, day)` of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds; pre-epoch clamps to the epoch).
fn format_ts(t: SystemTime) -> String {
    let secs = unix_secs(t);
    let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
    let in_day = secs.rem_euclid(SECS_PER_DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / 3_600,
        in_day % 3_600 / 60,
        in_day % 60
    )
}

/// Daily file name `audit-YYYY-MM-DD.jsonl` for the UTC date of `now` (pre-epoch instants name
/// the epoch day).
#[must_use]
pub fn audit_file_name(now: SystemTime) -> String {
    let (year, month, day) = civil_from_days(unix_secs(now).div_euclid(SECS_PER_DAY));
    format!("audit-{year:04}-{month:02}-{day:02}.jsonl")
}

/// The day number (days since the epoch) of a name of the exact form `audit-YYYY-MM-DD.jsonl`
/// with a real calendar date; `None` for every other name.
fn audit_file_day(name: &str) -> Option<i64> {
    let date = name.strip_prefix("audit-")?.strip_suffix(".jsonl")?;
    let mut fields = date.split('-');
    let (year, month, day) = (fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some() || [year.len(), month.len(), day.len()] != [4, 2, 2] {
        return None;
    }
    let number = |text: &str| {
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse::<i64>().ok())
            .flatten()
    };
    let (year, month, day) = (number(year)?, number(month)?, number(day)?);
    let days = days_from_civil(year, month, day);
    // An impossible date (month 13, Feb 30) does not survive the round trip.
    ((1..=12).contains(&month) && civil_from_days(days) == (year, month, day)).then_some(days)
}

/// Retention: remove audit files whose UTC date is more than `retain_days` days before today
/// (a file exactly `retain_days` old is kept). Only names of the exact form
/// `audit-YYYY-MM-DD.jsonl` with a valid calendar date are candidates; anything else is never
/// touched; the newest audit file is never removed. Returns the removed names, sorted ascending.
///
/// # Errors
/// [`AuditError::Io`] when listing or removing fails.
pub fn prune(
    store: &dyn LogStore,
    clock: &dyn Clock,
    retain_days: u32,
) -> Result<Vec<String>, AuditError> {
    let names = store.list().map_err(|e| AuditError::Io {
        reason: format!("listing the log directory failed: {e}"),
    })?;
    let mut dated: Vec<(i64, String)> = names
        .into_iter()
        .filter_map(|name| audit_file_day(&name).map(|day| (day, name)))
        .collect();
    dated.sort();
    let newest = dated.last().map(|(day, _)| *day);
    let cutoff = unix_secs(clock.now()).div_euclid(SECS_PER_DAY) - i64::from(retain_days);

    let mut removed = Vec::new();
    for (day, name) in dated {
        if day < cutoff && Some(day) != newest {
            store.remove(&name).map_err(|e| AuditError::Io {
                reason: format!("removing {name} failed: {e}"),
            })?;
            removed.push(name);
        }
    }
    Ok(removed)
}
