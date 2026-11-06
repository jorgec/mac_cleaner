# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cargo workspace skeleton (`cleaner-core`, `cleaner-macos`, `cleaner-cli`, `cleaner-testkit`).
- Pinned toolchain, rustfmt/clippy configuration (`disallowed-methods` ban on direct
  filesystem mutation and process spawning), `cargo-deny` policy (no network crates).
- GitHub Actions CI on arm64 macOS: fmt, clippy, tests, safety suite, supply chain,
  coverage, test-documentation checker, MSRV, docs.
- `scripts/check-test-docs.sh` enforcing the testing policy.
- Spec 001 behavior: `SafetyGuard` (deny list, ancestors, firmlink normalization, containment,
  symlink/device checks, fail-closed), JSONL audit log with daily files and retention pruning,
  `RealFs`/`FileAuditSink`/`FileLogStore` adapters, fail-closed `CLEANER_TEST_MODE` guard
  (exit 3 before argument parsing), and `cleaner --version` (name, version, git SHA, target).
- Spec 002 `cleaner scan [--rule ID]... [--tier TIER] [--top N] [--json]` (read-only): purgeable
  space via Foundation volume resource values (ADR 0002), local Time Machine snapshots via
  `tmutil listlocalsnapshots /`, per-rule reclaimable bytes for the 12 built-in rules, human and
  `scan/1` JSON output, Full Disk Access hint, gap-free audit log per run (never pruned by a scan),
  SIGINT -> exit 130, exit 4 for partial/unknown results. Test seams `CLEANER_TMUTIL` and
  `CLEANER_TEST_VOLUME` are honored only in test mode and refused (exit 3) otherwise.
- A rule root whose own `lstat` is denied (EACCES/EPERM, e.g. TCC-protected `ios-backups`) is
  reported `partial` with one `permission_denied` skip instead of `refused`.
