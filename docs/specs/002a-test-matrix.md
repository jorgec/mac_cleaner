# 002a - Test matrix (TDD red phase, CORE half of spec 002)
Companion to `docs/specs/002-purgeable-space-scan.md` (not part of the approved spec text).
Owner: tester. Binding: `testing-policy.md`, `safety-invariants.md`. Status: **RED** (the new behavior is
stubbed on purpose, see section 3). Slice 002b (adapters: `RealFs::read_dir`, Foundation volume query,
`tmutil` runner, clap CLI, human renderer, SIGINT, selectors, test-mode wiring) is **not** covered here.

Run: `scripts/with-scratch-home.sh cargo nextest run --workspace --locked` · safety gate: `-E 'test(safety)'` ·
docs gate: `scripts/check-test-docs.sh`. Per-function worksheets live in each test file's module header.

## 1. AC -> tests (all in `crates/cleaner-core/tests/` unless noted; all against `FakeFs`/fakes, never the real machine)

| AC | INV | Test (file :: name) | Level | Notes |
|----|-----|---------------------|-------|-------|
| 002-1 | 12,13 | `volume_purgeable.rs` `ac_002_1_purgeable_is_the_clamped_difference_never_above_total` | unit, table (7 rows) | I>A, I==A (not clamped), I==A-1 (clamped), I-A==T, I-A==T+1, u64 extremes |
| 002-3 | - | `ac_002_3_volume_is_queried_at_home_and_purgeable_is_reported_but_never_summed` | scan, 2 rows | one query at HOME; fields; clamp flag wiring; `totals` excludes purgeable |
| 002-2 | 13 | `ac_002_2_unknown_volume_is_null_never_zero_and_scanning_continues` | scan, 2 error kinds | `purgeable: null` in JSON, `volume_error` = kind, rule still scanned, exit 4 |
| 002-21 | - | `snapshots.rs` `ac_002_21_parser_names_dates_unparsed_and_the_header_are_handled` | unit, table (12 rows) | real header-only output, volume-group header, foreign line, header look-alikes, impossible dates/times, month lengths, leap 2000/2024 vs 2100, wrong separators/letters, near-miss patterns, CRLF/blank; **since 002b-fixups:** a valid non-leap February (`2026-02-28-120000` -> `2026-02-28T12:00:00`), which kills the `days_in_month` mutant that returned 29/30 for non-leap Februaries |
| 002-21 | 10 | `safety_ac_002_21_tmutil_is_invoked_read_only_with_args_array_and_timeout` | unit | one call, args array, 10 s, no sudo, no `delete*`/`thin*` |
| 002-21 | 13 | `ac_002_21_tool_failures_are_errors_with_stable_kinds_not_empty_lists` | unit, table (4) | `tool_missing`, `timeout`, `spawn_failed`, `nonzero_exit` |
| 002-21/20 | 13 | `ac_002_21_scan_reports_snapshots_as_empty_listed_or_unknown` | scan, 3 rows | `[]` vs listed (+unparsed, note) vs `null`+error+exit 4 |
| 002-11 | 05 | `rules_table.rs` `ac_002_11_table_matches_the_spec_pin` | data pin | 12 rules, order, tiers, roots, min_age 90 d, user-logs excludes |
| 002-11 | 05,06 | `safety::ac_002_11_table_invariants_hold_for_every_rule` | data-driven | unique kebab ids, explain, relative clean roots, `admit_root` for every root, Report-only not deletable, no shared root |
| 002-9 | 12 | `safety::ac_002_9_owner_of_follows_the_spec_table` | unit, table (20) | most-specific, component-wise (`Caches-old`), excluded own logs, ancestors unclaimed |
| 002-9/22 | 12 | `safety::ac_002_9_owner_of_logic_longest_root_component_wise_excludes_and_ties` | unit, table x2 orders | nesting independent of table order, tie -> earlier rule, excluded subtree |
| 002-4 | 12 | `scan_walk.rs` `ac_002_4_allocated_bytes_logical_bytes_zero_byte_files_and_uncounted_nodes` | scan | blocks*512, logical, zero-byte = 1 item, sparse, dirs/sockets uncounted |
| 002-4 | 12 | `ac_002_4_sums_saturate_instead_of_overflowing` | scan | `blocks=u64::MAX`, two near-max files, tier totals |
| 002-4 | 12 | `safety::ac_002_4_hardlinks_are_counted_once_per_dev_ino_in_rule_order` | scan, 2 rule orders | same/other rule, `(dev,ino)` not ino alone, `deduped_links` attribution |
| 002-5 | 07 | `safety::ac_002_5_symlinks_count_as_links_and_are_never_entered` | scan | dir/file/dangling/self-loop/parent-loop links; no `read_dir`/`lstat` behind a link |
| 002-5/11 | 06,07 | `safety::ac_002_11_roots_refused_by_the_guard_are_never_listed` | scan | symlinked root, deny-listed root, `..` root, absolute root outside HOME -> `refused`, never listed |
| 002-6 | 08 | `safety::ac_002_6_a_directory_on_another_device_is_not_entered_and_is_reported` | scan | direct + nested mount not listed, `cross_device` skip records, root's own device is the baseline |
| 002-7 | 09,10 | `safety::ac_002_7_unreadable_entries_are_skipped_once_logged_and_the_walk_continues` | scan, table (6) | lstat EPERM/EACCES on file/dir, read_dir EPERM/EACCES, EIO; one attempt; no sudo |
| 002-7 (root) | 09,13 | `safety::ac_002_7_root_permission_error_is_partial_other_root_errors_and_verdicts_stay_refused` | scan, table (6) | **added after the ratified "permission on the root itself" rule**: root `lstat` EACCES / EPERM -> `partial`, 0 bytes, ONE `skipped{permission_denied}` (not `refused`); root `lstat` EIO, a deny-listed root that also returns EACCES (verdict wins) and a symlinked root stay `refused`/`root_refused`; two-root rule with one denied root keeps counting the other (4096 B, `partial`); nothing below an unreadable/refused root is listed. **RED on the 002a core** (it refuses on any non-ENOENT `Io`): the developer must change root admission, not the test |
| 002-8 | - | `ac_002_8_vanished_entries_are_counted_not_errors` | scan, 2 rows | file ENOENT on lstat, dir ENOENT on listing; not partial, exit 0 |
| 002-10 | - | `ac_002_10_absent_roots_are_reported_absent_not_as_errors` | scan | all-absent vs one-of-two roots; `scan_result` status `absent` |
| 002-12 | - | `ac_002_12_age_filter_counts_only_old_enough_regular_files` | scan | threshold, +-1 s, future, epoch, symlink, dir mtime irrelevant, rule without min_age |
| 002-22 | 16 | `safety::ac_002_22_excluded_subtrees_contribute_nothing_and_lookalikes_do_count` | scan | nested excluded files; `mac-cleaner-extra`, `mac-cleaner.txt` still count |
| 002-9 | 12 | `safety::ac_002_9_nested_roots_are_claimed_by_the_most_specific_rule_without_double_counting` | scan, 2 rule orders | 3-level nesting, `Caches-old` under no root, sum == union |
| 002-9 | 12 | `safety::ac_002_9_property_rule_sums_equal_the_union_of_roots` | **proptest (64 cases)** | random trees x nested/absent roots x hardlink groups vs an independent oracle |
| 002-13 | - | `ac_002_13_top_children_are_ordered_by_bytes_then_path_and_limited_by_n` | scan, N in {4,0,10} | tie order by path **bytes** (`B` < `a`), pooled roots, child dir = recursive sum; **since 002b-fixups:** an empty directory and a zero-byte file among the children never appear even with spare slots (N=10), ratified D15 (kills the `retain(bytes > 0)` mutant) |
| 002-13 | - | `ac_002_13_results_do_not_depend_on_directory_listing_order` | scan, fwd vs reversed listing | hardlink attribution + ties are listing-order independent |
| (FM) | - | `fm_002_deep_tree_of_10000_levels_is_walked_iteratively` | scan on a 256 KiB-stack thread | recursion would overflow |
| 002-17 | 11 | `scan_audit.rs` `ac_002_17_a_run_writes_start_one_result_per_rule_and_end_with_gapless_seq` | scan + audit decode | run_start fields, per-rule scan_result counters, skipped between, run_end exit code/totals, gap-free seq, one run_id |
| 002-17 | 11 | `ac_002_17_skipped_records_are_capped_at_1000_per_run_and_the_overflow_is_counted` | scan, rows (1000,0) (1001,0) (600,600) | cap per **run**, `skipped_unlogged` per rule |
| 002-17 | 13 | `ac_002_17_scan_completes_and_flags_audit_unavailable_when_the_sink_fails` | scan, 3 rows | no log / failing sink / healthy: `audit_unavailable`, exit 4/4/0 |
| 002-15 | 01,10 | `safety::ac_002_15_a_scan_leaves_the_tree_untouched_and_runs_only_the_read_only_command` | scan | `FakeFs::snapshot()` before == after (content+mtime+ino), only `listlocalsnapshots /` run, repeatable |
| 002-18 | - | `ac_002_18_cancelling_stops_listing_and_reports_an_incomplete_interrupted_run` | scan, 2 rows | pre-cancelled; cancelled during the 3rd listing; `incomplete`/`interrupted`, exit 130, `run_end.interrupted` |
| 002-16 | - | `scan_report.rs` `ac_002_16_json_schema_scan_1_pins_key_names_and_order` | schema pin | every `(depth,key)` in document order (no snapshot crate needed) |
| 002-20 | - | `ac_002_20_notes_are_the_four_stable_codes_plus_the_snapshot_code_when_listed` | scan, 2 rows | exact code list and order |
| 002-16 | 16 | `ac_002_16_non_utf8_paths_carry_path_b64_and_utf8_paths_do_not` | scan | independent base64 oracle; no `path_b64` key for clean paths |
| 002-16 | 12 | `ac_002_16_totals_are_per_tier_sums_of_rule_bytes` | scan | safe/caution/report-only |
| 002-2,7,8,10,17,18,21 | 13 | `ac_002_exit_code_policy_130_interrupted_4_partial_or_unknown_0_otherwise` | unit, table (10) | each trigger; absent/vanished stay 0; 130 beats 4 |
| (infra) | - | `cleaner-testkit/tests/fake_fs.rs` `read_dir_and_attributes_model_what_the_scanner_relies_on` | sanity | `read_dir` follows a final symlink (opendir), list-only errors, sparse, hardlink `ino`/`nlink`, reversed listing |

38 new tests (37 spec + 1 fake sanity; 37 red, the fake sanity test is green). 46 existing tests unchanged in behavior (the audit tests' record literals gained the
new fields, see section 2). Safety gate (`test(safety)`): 13 of the new tests (all red). After the developer's 002a implementation (84 tests green) the
002b-fixups added **one** test (root permission, section 9) and two table rows (non-leap February, zero-byte `top` children): 85 tests, 1 intentionally red.
Not part of 002a (slice 002b): AC-002-14 selectors, AC-002-16 human/NO_COLOR/`--json` plumbing, AC-002-19 test-mode guard on
`scan`, SIGINT at the process level, FDA hint text, `RealFs::read_dir`, the Foundation volume adapter, the real `tmutil` runner.

## 2. API the developer must implement (types/signatures are real; bodies marked `STUB` are the work)

```rust
// cleaner-core::ports  (REAL, new)
pub struct Metadata { kind: FileKind, dev: u64, ino: u64, blocks: u64 /*512-byte units*/, len: u64, mtime: SystemTime, nlink: u32 }
pub struct DirEntry { pub name: OsString, pub kind: FileKind }
trait Fs { fn lstat(&self, &Path) -> io::Result<Metadata>; fn read_dir(&self, &Path) -> io::Result<Vec<DirEntry>>; } // still read-only; read_dir = opendir semantics (FOLLOWS a final symlink)
pub struct VolumeCaps { mount_point, total, available, available_important, available_opportunistic }
pub enum VolumeError { NotFound{path}, PermissionDenied, QueryFailed{reason} }  // .kind() -> "not_found"|"permission_denied"|"query_failed"
trait VolumeCapacity { fn query(&self, &Path) -> Result<VolumeCaps, VolumeError>; }
pub struct CommandOutput { exit_code: i32, stdout: Vec<u8>, stderr: Vec<u8> }
pub enum CommandError { NotFound, TimedOut, Failed{reason} }
trait CommandRunner { fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<CommandOutput, CommandError>; } // non-zero exit is Ok(output)
// cleaner-core::cancel (REAL)
CancelToken::{new, cancel, is_cancelled}   // Clone, shared flag
// cleaner-core::audit (REAL extension; encode/decode already implemented)
Record::ScanResult { rule_id, status, bytes, items, counts: ScanCounts{logical_bytes, skipped, skipped_unlogged, vanished, deduped_links} }
Record::RunEnd { exit_code, interrupted, total_bytes, total_items }        // wire fields are flat; new ones default to 0 on decode
// cleaner-core::rules  (types REAL; builtin/owner_of STUB)
enum Tier { Safe, Caution, ReportOnly }  // serde "safe" | "caution" | "report-only"; .as_str()
struct Rule { id: String, tier: Tier, roots: Vec<PathBuf>, excludes: Vec<PathBuf>, min_age: Option<Duration>, explain: String, deletable: bool }  // roots/excludes relative to HOME
Rule::new(id, tier, roots: &[&str]) -> Rule   // REAL helper: no excludes, no min_age, explain "test rule", deletable = tier != ReportOnly
fn builtin() -> Vec<Rule>                                     // STUB: the 12 spec rules, spec order
fn owner_of<'a>(rules: &'a [Rule], rel: &Path) -> Option<&'a Rule>   // STUB: longest component-wise root wins, excludes unclaim, tie -> earlier rule
// cleaner-core::volume
struct Purgeable { bytes: u64, clamped: bool }; fn purgeable(&VolumeCaps) -> Purgeable   // STUB
// cleaner-core::snapshots
struct Snapshot { name: String, date: Option<String> /*YYYY-MM-DDTHH:MM:SS*/, bytes: Option<u64> }; struct ParsedSnapshots { snapshots, unparsed: u64 }
fn parse_listlocalsnapshots(&str) -> ParsedSnapshots                                  // STUB
fn list_local_snapshots(&dyn CommandRunner) -> Result<ParsedSnapshots, SnapshotsError>  // STUB (consts TMUTIL_PROGRAM="/usr/bin/tmutil", TMUTIL_ARGS, TMUTIL_TIMEOUT=10 s are real)
enum SnapshotsError { ToolMissing, NonZeroExit{code}, TimedOut, SpawnFailed{reason} }  // .kind() -> tool_missing|nonzero_exit|timeout|spawn_failed
// cleaner-core::report  (REAL data model; only exit_code is STUB)
struct ScanReport { schema, run_id, home, home_b64, volume: VolumeReport, snapshots: Option<Vec<Snapshot>>, snapshots_unparsed, snapshots_error, rules: Vec<RuleReport>, totals: TierTotals, notes: Vec<String>, incomplete, interrupted, audit_unavailable }
fn ScanReport::exit_code(&self) -> i32          // STUB: 130 interrupted > 4 (rule partial|refused|interrupted, purgeable None, snapshots None, audit_unavailable) > 0
enum RuleStatus { Ok, Partial, Absent, Refused, Interrupted }   // as_str(): ok|partial|absent|refused|interrupted
consts: SCHEMA="scan/1", NOTE_*, SKIP_PERMISSION_DENIED|SKIP_CROSS_DEVICE|SKIP_IO_ERROR|SKIP_ROOT_REFUSED
// cleaner-core::scan
struct ScanPorts<'a> { fs: &dyn Fs, clock: &dyn Clock, volume: &dyn VolumeCapacity, runner: &dyn CommandRunner }   // no mutating port by construction
struct ScanOptions { home: HomeDir, rules: Vec<Rule>, top_n: usize, argv: Vec<String>, version: String, run_id: RunId }
fn run_scan(&ScanPorts, &ScanOptions, &CancelToken, audit: Option<&mut AuditLog>) -> ScanReport   // STUB (None = sink could not be opened)
consts: DEFAULT_TOP_N = 5, MAX_SKIPPED_RECORDS = 1000
// cleaner-testkit (REAL): FakeFs{file_sized,size,mtime_secs,hardlink,ino,deep_dirs,list_error_at,reverse_read_dir,record_calls,read_dir_calls,snapshot}, deep_path, FakeVolume, FakeRunner, RecordedCommand
// cleaner-macos: Fs::lstat fills the new fields (real, trivial); RealFs::read_dir is a STUB returning Unsupported (002b)
```

## 3. Stub inventory (all marked `STUB`; replace every one)
core: `rules::{builtin, owner_of}`, `volume::purgeable`, `snapshots::{parse_listlocalsnapshots, list_local_snapshots}`,
`report::ScanReport::exit_code`, `scan::run_scan` (stub reports every rule `ok` with zero bytes, touches no port, writes no
audit record, `purgeable: Some(0)`). macos: `RealFs::read_dir`. The audit wire format for the new fields is already real.

## 4. Dependencies
None added. (`serde_json`/`base64`/`proptest` already present; the JSON key-order pin uses a 25-line tokenizer instead of
`insta`/`preserve_order`.) Deliberately not added: `clap`, `ulid`, `objc2*` (slice 002b). `cargo deny check` passes.

## 5. Decisions the tester took where the spec is silent (orchestrator: ratify or amend)
- **D1 Rule statuses**: `ok | partial | absent | refused | interrupted`. `absent` iff *no* root of the rule exists; one existing root of several
  makes the rule `ok`/`partial` (AC-002-10). `refused`: a root the guard refuses or that is not relative (see D2). `interrupted`: a rule that was in
  flight or not yet started when the cancel token fired (AC-002-18). Each rule still gets a `scan_result` record.
- **D2 Scan-time root admission** (INV-06/07): every root is `home.join(rel)` only if `rel` is relative, and must pass `admit_root`; a symlinked, deny-listed,
  `..`-containing or absolute root yields status `refused`, 0 bytes, never listed, one `skipped{reason:"root_refused"}` record, exit 4. Spec 002 does
  not say what a symlinked root does; refusing is the fail-closed reading.
- **D3 Skip reasons**: `permission_denied` (EPERM/EACCES), `cross_device`, `io_error` (any other error, e.g. EIO: **beyond the spec**), `root_refused`.
  Not asserted: whether `cross_device` makes the rule `partial` (AC-002-6 is silent, CLI table says "skips -> 4"); the tests only pin its record, tally and
  non-descent.
- **D4 `skipped` cap** is **per run** (as the spec words it), counted in rule order; `skipped_unlogged` is the per-rule overflow. `skipped` in the report counts all skips.
- **D5 Items**: a counted regular file or symlink is one item; a second sighting of a hardlinked inode is not an item (it is `deduped_links`); directories and other
  node kinds are never counted.
- **D6 `purgeable_clamped` also flags capping at `total`** (value altered), not only `I < A`. Only `I < A` is spec text.
- **D7 `min_age` rules count regular files only** (spec table: "only regular files"): an old *symlink* under `old-downloads` is not counted.
- **D8 Snapshot parsing**: the `Snapshots for ...:` header and blank lines are not snapshots (verified against real `tmutil` output on macOS 15: header only when there
  are none); `date` is local time `YYYY-MM-DDTHH:MM:SS`, calendar-validated; `snapshot_sizes_unavailable` is emitted iff at least one snapshot is listed; `snapshots_unparsed` is a
  top-level count; failure kinds `tool_missing | nonzero_exit | timeout | spawn_failed`. Program is the absolute `/usr/bin/tmutil`.
- **D9 JSON shape** (spec gives only some keys): `volume{mount_point,total,available,available_important,purgeable,purgeable_clamped,volume_error}` (all `null` when unknown),
  top-level `snapshots`, `snapshots_unparsed`, `snapshots_error`, `totals{safe,caution,report-only}`, `rules[]{id,tier,status,bytes,logical_bytes,items,skipped,skipped_by_reason,
  vanished,deduped_links,top[]{path,path_b64?,bytes}}`, `home`/`home_b64?`; `top` paths are absolute. The exact key order is pinned by
  `ac_002_16_json_schema_scan_1_pins_key_names_and_order`.
- **D10 Exit-code policy lives in core** (`ScanReport::exit_code`), so the CLI is thin: 130 > 4 > 0; absent roots and vanished entries are 0.
- **D11 Audit record extension**: `scan_result` gains `logical_bytes, skipped, skipped_unlogged, vanished, deduped_links`; `run_end` gains `total_bytes, total_items`
  (sum over all rules, never purgeable). `skipped` records carry no `rule_id` (unchanged from 001).
- **D12 Deterministic walk**: entries are examined in ascending byte order of their names; ties in `top` break by full path bytes.
- **D13 `owner_of` with excludes**: an excluded subtree is not claimed by the excluding rule, but a rule with a shorter enclosing root may claim it. Documented, one row in the
  unit table (`h/x/z`, `e/skip/q` give `None` only because nothing encloses them); no built-in rule combines the two, so the tests do not depend on it.
- **D14 Cancellation granularity**: the token is polled before every directory listing; the batch (one listing) in flight finishes. Tests assert no listing after the cancelling one.

## 6. Not tested on purpose
- Real I/O (`RealFs::read_dir`, `lstat` of the new fields, Foundation, `tmutil`): slice 002b with `#[cfg(target_os = "macos")]` tests.
- Non-regular node kinds beyond "not counted"; entries with non-UTF-8 names *inside the walk* beyond the `path_b64` report test; APFS clones (documented caveat).
- Ordering of `skipped` records relative to the same rule's `scan_result` (spec silent); `seq`/`ts` of records beyond gap-freeness (spec 001 covers the envelope).
- Mid-run audit write failures that start *after* some writes (the in-memory sink cannot express "fail after N"); the `None` and always-failing sink cover the policy.
- A compile-fail test for "ScanPorts has no mutating port": reviewed by API surface (a `trybuild` test would pass on unrelated errors).
- Human output, units, `NO_COLOR`, FDA hint: CLI.
- Performance beyond the 10 000-level depth test (no timing assertions).

## 7. Infrastructure changes (real code, reviewed, not stubs)
`cleaner-core::ports` (`Metadata` extended; `Fs::read_dir`; `VolumeCapacity`; `CommandRunner`), `cleaner-core::cancel`, `cleaner-core::audit` (new record fields, `encode_path`
now `pub(crate)`), `cleaner-testkit::FakeFs` (rewritten internally: byte-keyed nodes, per-dir child index, fast lookup path while the fake has no symlink/error, so a
10 000-level chain costs ~1-2 s; existing public behavior unchanged, all 46 old tests pass), `FakeVolume`, `FakeRunner`; `cleaner-macos::RealFs::lstat` fills the new fields.
Existing tests touched: `audit_log.rs` only (record literals gained the new fields; the round-trip now exercises non-zero counters).

## 8. Validation of the tests themselves (tester, throwaway)
To prove the tests are satisfiable and sharp, the tester wrote a **throwaway reference implementation** of every stub (not kept; the stubs above were
restored byte-for-byte): all 84 tests were green against it, then `cargo mutants` (scratch HOME, nextest) ran on `scan.rs`, `rules.rs`, `volume.rs`, `snapshots.rs`,
`report.rs`: 131 mutants, 115 caught, 7 unviable, 9 missed. The missed ones were: 6 parser mutants (fixed by 3 new parser rows: header look-alikes, wrong separators/letters,
month lengths; re-run: `snapshots.rs` 52 mutants, 50 caught, 2 unviable, 0 missed), `Tier::as_str` (unused helper, removed), a `Debug` impl, and `nlink > 1` -> `>= 1`
(equivalent: only an optimization of the dedupe set). The developer should re-run mutants on the real implementation; the reference run is evidence for the test
suite, not for the product code.

## 9. 002b fixups to this slice (tests only; the implementation is the developer's)
Found while writing spec 002b (real `TCC`-protected roots such as `ios-backups`) and by the mutation run of the reference implementation:
1. `snapshots.rs` parser table: new row `valid non-leap February` (kills the `days_in_month` mutant).
2. `scan_walk.rs` `ac_002_13_top_children...`: zero-allocation children (empty dir, zero-byte file) are never in `top` (ratified D15). Passes today; it pins the `retain(bytes > 0)`.
3. `scan_walk.rs` `safety::ac_002_7_root_permission_error_is_partial_other_root_errors_and_verdicts_stay_refused` (new, **intentionally RED**): implements the ratified rule
   "`lstat` of a *root* failing with EACCES/EPERM -> `partial` + one `skipped{permission_denied}`, not `refused`; guard verdicts and other errnos on the root stay `refused`".
   What the developer must change: `scan.rs::admit_root` maps every `Err(Denied)` to `Admission::Refused`. `SafetyGuard::admit_root` reports every non-ENOENT `lstat` failure as
   `DeniedKind::Io` **without the errno** (`Denied{kind, path}`), so the scanner cannot tell EACCES from EIO. Options (developer's choice, all keep the 001 guard tests green): (a) re-`lstat`
   the root in `admit_root` when the verdict is `Io` and look at the `io::Error` kind (what the reference implementation did: 8 lines, one extra `lstat` only on the failure path); (b) add the
   `io::ErrorKind`/errno to `Denied` (touches spec 001 types: needs an orchestrator nod). A deny-listed root that also gives EACCES stays `refused` because the guard's lexical checks run first.
   Matrix doc impact: D2 (above) says "any root the guard refuses -> `refused`": read it as "any *guard verdict*"; permission errors on the root are D3's `permission_denied` skip.
   A rule whose only root is denied is `partial` (not `absent`): `absent` is reserved for roots that do not exist.
