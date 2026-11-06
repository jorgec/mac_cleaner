//! Shared scan-test infrastructure (spec 002a). Not a test file: fixtures and a harness that wire
//! the fakes to `run_scan`. Every helper states what it builds and guarantees.
#![allow(dead_code)] // each test binary uses a different subset

use std::path::PathBuf;
use std::sync::Arc;

use cleaner_core::audit::{AuditLog, DecodedRecord, decode_line};
use cleaner_core::cancel::CancelToken;
use cleaner_core::ports::{Fs, RunId};
use cleaner_core::report::{RuleReport, ScanReport};
use cleaner_core::rules::Rule;
use cleaner_core::safety::HomeDir;
use cleaner_core::scan::{ScanOptions, ScanPorts, run_scan};
use cleaner_testkit::{FakeFs, FakeRunner, FakeVolume, FixedClock, MemorySink};

/// The injected home used by every scan test.
pub const HOME: &str = "/Users/u";
/// The frozen "now" of the harness clock: 2027-01-15T08:00:00Z.
pub const NOW: i64 = 1_800_000_000;
/// Seconds in a day.
pub const DAY: i64 = 86_400;
/// `tmutil` output of a machine without local snapshots (captured from a real macOS 15 host).
pub const TMUTIL_NO_SNAPSHOTS: &str = "Snapshots for disk /:\n";

/// `blocks` (512-byte units) that make exactly `bytes` allocated bytes. `bytes` must be a
/// multiple of 512.
#[must_use]
pub const fn blocks(bytes: u64) -> u64 {
    bytes / 512
}

/// Absolute path of `rel` below the test home.
#[must_use]
pub fn home(rel: &str) -> PathBuf {
    PathBuf::from(HOME).join(rel)
}

/// Everything a scan needs, with deterministic defaults: healthy volume, `tmutil` with no
/// snapshots, clock frozen at [`NOW`], an in-memory audit sink.
pub struct Harness {
    /// The scanned filesystem.
    pub fs: FakeFs,
    /// The volume port.
    pub volume: FakeVolume,
    /// The command port.
    pub runner: FakeRunner,
    /// The clock (also stamps audit records).
    pub clock: Arc<FixedClock>,
    /// The audit sink; clones share the lines, so tests can read what the scan wrote.
    pub sink: MemorySink,
}

/// Healthy defaults around `fs`.
#[must_use]
pub fn harness(fs: FakeFs) -> Harness {
    Harness {
        fs,
        volume: FakeVolume::with_numbers(
            "/System/Volumes/Data",
            500_000_000_000,
            300_000_000_000,
            304_000_000_000,
        ),
        runner: FakeRunner::ok(TMUTIL_NO_SNAPSHOTS),
        clock: Arc::new(FixedClock::from_unix_secs(NOW)),
        sink: MemorySink::new(),
    }
}

impl Harness {
    /// Replace the volume port.
    #[must_use]
    pub fn with_volume(mut self, volume: FakeVolume) -> Self {
        self.volume = volume;
        self
    }

    /// Replace the command port.
    #[must_use]
    pub fn with_runner(mut self, runner: FakeRunner) -> Self {
        self.runner = runner;
        self
    }

    /// Scan `rules` on the harness filesystem with a fresh (un-cancelled) token and a working
    /// audit log writing into `self.sink`.
    pub fn scan(&self, rules: &[Rule], top_n: usize) -> ScanReport {
        self.run(&self.fs, rules, top_n, &CancelToken::new(), true)
    }

    /// Full control: scan through `fs` (the harness `FakeFs` or a wrapper around it), with
    /// `cancel`, and with (`audit == true`) or without (`false`: sink unavailable) an `AuditLog`.
    pub fn run(
        &self,
        fs: &dyn Fs,
        rules: &[Rule],
        top_n: usize,
        cancel: &CancelToken,
        audit: bool,
    ) -> ScanReport {
        let ports = ScanPorts {
            fs,
            clock: self.clock.as_ref(),
            volume: &self.volume,
            runner: &self.runner,
        };
        let opts = ScanOptions {
            home: HomeDir::new(HOME),
            rules: rules.to_vec(),
            top_n,
            argv: vec!["cleaner".to_owned(), "scan".to_owned()],
            version: "0.0.0-test".to_owned(),
            run_id: RunId::new("RUN-0001"),
        };
        let mut log = AuditLog::new(
            Box::new(self.sink.clone()),
            self.clock.clone(),
            RunId::new("RUN-0001"),
        );
        run_scan(&ports, &opts, cancel, audit.then_some(&mut log))
    }

    /// The audit records written so far, decoded (panics on an undecodable line: that is a bug).
    pub fn records(&self) -> Vec<DecodedRecord> {
        self.sink
            .lines()
            .iter()
            .map(|l| decode_line(l).unwrap_or_else(|e| panic!("undecodable audit line {l}: {e}")))
            .collect()
    }
}

/// The report of rule `id`; fails the calling test with a clear message when it is missing.
pub fn rule_report<'a>(report: &'a ScanReport, id: &str) -> &'a RuleReport {
    let found = report.rules.iter().find(|r| r.id == id);
    assert!(
        found.is_some(),
        "the report has no entry for rule `{id}` (rules present: {:?})",
        report
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>()
    );
    found.unwrap_or_else(|| unreachable!("asserted above"))
}
