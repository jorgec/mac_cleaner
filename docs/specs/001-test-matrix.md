# 001 - Test matrix (TDD red phase)
Companion to `docs/specs/001-workspace-skeleton-and-guards.md` (not part of the approved spec text).
Owner: tester. Binding: `testing-policy.md`, `safety-invariants.md`. Status: **RED** (all behavior
bodies are deliberate stubs; see "Stub inventory"). Updated after the orchestrator's amendments
(fail-closed test-mode guard; absent roots admitted with `exists=false`): see section 8.

Run: `cargo nextest run --workspace` · safety gate: `-E 'test(safety)'` · docs gate: `scripts/check-test-docs.sh`.
Per-function worksheets live in each test file's module header.

## 1. AC -> tests

| AC | INV | Test (file :: name) | Level | Notes |
|----|-----|---------------------|-------|-------|
| 001-1 | 06 | `core/tests/safety_guard.rs` `safety::ac_001_1_every_builtin_entry_and_its_descendants_are_deny_listed` | unit, table (14 entries x 3 candidates) | also asserts zero `Fs` calls and `Denied.path == candidate` |
| 001-1 | 06 | `safety::ac_001_1_lookalike_siblings_of_denied_names_are_not_denied` | unit, table | success-side boundary (`Documents-old`, `Documentsx`, `/Systems`) |
| 001-2 | 06 | `safety::ac_001_2_ancestors_of_denied_paths_are_denied_even_outside_the_root` | unit, table | pins precedence deny list > containment |
| 001-2 | 06 | `safety::ac_001_2_sibling_of_a_denied_path_is_admitted` | unit | `Library/Caches` under `Library` |
| 001-3 | 06 | `safety::ac_001_3_firmlink_prefix_is_treated_identically` | unit, table | denied/allowed/both/`Data` itself; SafePath is normalized |
| 001-3 | 06 | `safety::ac_001_3_normalize_is_idempotent_and_never_flips_a_verdict` | **proptest** | idempotence, verdict(p)==verdict(normalize(p))==verdict(DATA+p) |
| 001-4 | 07 | `safety::ac_001_4_relative_empty_and_dotdot_paths_are_rejected_before_anything_else` | unit, table | NotAbsolute/Traversal, `..` that resolves inside root, Traversal beats DenyListed |
| 001-4 | 07 | `safety::ac_001_4_redundant_separators_and_dots_are_normalized_not_rejected` | unit, table | compares raw `OsStr` (Path eq hides `//`) |
| 001-4 | 07 | `safety::ac_001_4_hostile_names_are_judged_by_the_same_rules_without_panic` | unit, table | space, `\n`, `-rf`, NFD vs NFC, non-UTF-8, 255 bytes, `...`; non-UTF-8 under Documents |
| 001-5 | 07 | `safety::ac_001_5_containment_is_component_wise_and_the_root_is_not_a_candidate` | unit, table | `Caches-old`, `Cachesx`, root, root with `/`, unrelated |
| 001-5 | 07 | `safety::ac_001_5_admit_root_accepts_a_clean_root_and_refuses_denied_or_ancestor_roots` | unit, table | existing roots (`exists()==true`); needed by spec 002 AC-002-11 |
| 001-5 (amend.) | 07 | `safety::ac_001_5_admit_root_admits_a_missing_root_flagged_not_existing` | unit, table | `Ok`, `exists()==false`, normalized path |
| 001-5 (amend.) | 06 | `safety::ac_001_5_admit_root_refuses_a_denied_root_even_when_it_does_not_exist` | unit, table | empty fs: denied/ancestor/relative still refused, zero `Fs` calls |
| 001-17 | 06 | `safety::ac_001_17_deny_matching_survives_apfs_case_and_normalization_aliasing` | unit, table (14 + 5 rows, 2 guards) | case variants of fixed and home entries, `KEYCHAINS`, case-variant ancestors, NFD/upper-case home and extra entry (NFC `Caf\u{e9}`), admitted look-alikes (`Documents-old`, `Documentsx`, `documents-old`), containment stays exact (`OutsideRoot` for case-different candidate); zero `Fs` calls on lexical verdicts. The NFC/NFD hostile-name test (AC-001-4) stays valid: it uses a non-denied name and pins *admission* distinctness. |
| 001-18 | 06 | `safety::ac_001_18_private_aliases_are_rewritten_only_when_leading` | unit, table (15 rows + 2 guard rows) | `/var`,`/etc`,`/tmp` -> `/private/..` (also after the firmlink prefix), look-alikes and non-leading components unchanged, idempotence per row, `/var/db/x` is `DenyListed`; the AC-001-3 proptest alphabet now includes `var,tmp,etc,private,db` |
| 001-6 | 07 | `safety::ac_001_6_final_symlink_is_admitted_as_a_link_and_never_traversed` | unit | live/dangling/loop/2-cycle/inside-root links; no `lstat` below a link |
| 001-6 | 07 | `safety::ac_001_6_symlink_in_a_parent_component_is_a_symlink_escape` | unit, table | to-Documents, to-inside-root (conservative), self-loop, 2-cycle |
| 001-6 | 07 | `safety::ac_001_6_symlinked_root_is_a_symlink_escape_for_both_entry_points` | unit | `admit` and `admit_root` |
| 001-6 | 07 | `macos/tests/safety_real_fs.rs` `safety::inv_07_lstat_reports_kind_and_device_and_never_follows_symlinks` | real-adapter (temp dir) | `RealFs`; also `st_dev` |
| 001-7 | 08 | `safety::ac_001_7_candidate_or_parent_on_another_device_is_cross_device` | unit, table | same dev, mount point, below mount, parent differs, root on dev 3 |
| 001-8 | 06 | `safety::ac_001_8_extra_denied_paths_add_to_the_builtin_list_and_never_replace_it` | unit, table | "no remove API" half is compile-level, not tested |
| 001-9 | 07 | `safety::ac_001_9_toctou_every_admit_re_resolves_through_the_fs` | unit (stateful fake) | Ok -> SymlinkEscape -> Io; `lstat` count strictly grows |
| 001-10 | 13 | `safety::ac_001_10_any_fs_error_fails_closed_as_io` | unit, table | EACCES/EIO/ENAMETOOLONG/missing candidate/missing parent; `admit_root` EACCES on root, and a missing root whose parent gives EACCES (not "absent") |
| 001-11 | 11 | `core/tests/audit_log.rs` `ac_001_11_every_record_is_one_json_line_with_gapless_seq_and_clock_stamped_ts` | unit | all four kinds, schema, run_id, seq, ts per record; **plus `decode_line` round trip of all four kinds** (`u64::MAX` bytes, exit 130/interrupted) |
| 001-11 | 11 | `ac_001_11_embedded_newline_in_a_path_stays_on_one_line_and_round_trips` | unit | log-forging guard + encode/decode round trip |
| 001-11 | 11 | `ac_001_11_decode_tolerates_unknown_future_fields` | unit | reader forward-compat |
| 001-11 | 11,13 | `ac_001_11_seq_does_not_advance_when_the_write_fails` | unit | gap-free under failure (resolved ambiguity A8) |
| 001-11 | 11 | `ac_001_11_pre_epoch_clock_is_clamped_and_never_panics` | unit | spec failure mode |
| 001-12 | 11,13 | `macos/tests/audit_file.rs` `ac_001_12_open_creates_private_dir_0700_and_private_file_0600` | real fs (temp) | dir+missing parents created at open |
| 001-12 | 11 | `ac_001_12_each_record_is_flushed_before_write_line_returns` | real fs (temp) | reads via another handle while sink alive |
| 001-12 | 11 | `ac_001_12_existing_log_is_appended_to_never_truncated_even_with_two_writers` | real fs (temp) | pre-existing content + interleaved writers (O_APPEND) |
| 001-12 | 13 | `ac_001_12_unusable_location_is_reported_as_unavailable` | real fs (temp), table | parent-is-a-file; dir occupies file name |
| 001-13 | 16 | `core/tests/audit_log.rs` `ac_001_13_non_utf8_paths_are_recorded_losslessly_and_utf8_paths_are_not_duplicated` | unit, table | `path_b64` decoded with the base64 crate as independent oracle |
| 001-14 | 11 | `core/tests/audit_retention.rs` `ac_001_14_daily_file_name_follows_the_utc_date_of_the_instant` | unit, table | UTC midnight, leap day, year end; + 2100-02-28/03-01, 2399-12-31, 2400-02-29, 2038-01-19T03:14:08, 9999-12-31 |
| 001-14 | 11 | `ac_001_14_prune_removes_only_audit_files_older_than_the_cutoff` | unit, table | 91 vs 90 days, 12 decoy names incl. impossible days (`02-30`, `04-31`, `2023-02-29`, `1900-02-29`, month `00`) and two real leap days that must be accepted (`2000-02-29`, `2024-02-29`) |
| 001-14 | 11 | `ac_001_14_prune_never_removes_the_newest_audit_file` | unit | two-old and one-old scenarios |
| 001-14 | 11 | `ac_001_14_prune_cutoff_is_exact_across_leap_year_edges` | unit, table (5 rows) | 2100 (non-leap) and 2400 (leap) cutoffs, 9999 far future; added to kill date-maths mutants |
| 001-14 | 07 | `macos/tests/safety_log_store.rs` `safety::ac_001_14_list_and_remove_act_on_exactly_the_named_entry` | real fs (temp) | adapter happy path |
| 001-14 | 07 | `safety::ac_001_14_remove_refuses_names_that_could_leave_the_directory` | real fs (temp), table | `../x`, absolute, `.`, `..`, `a/b`, `""` |
| 001-15 | 15 | `core/tests/safety_testmode.rs` `safety::ac_001_15_only_unset_empty_or_zero_leave_the_guard_off` | unit, table | 11 raw values incl. `true`, `yes`, `foo`, `00`, ` 0`, non-UTF-8 -> ON (fail-closed) |
| 001-15 | 15 | `safety::ac_001_15_test_mode_refuses_homes_outside_the_system_temp_dir` | unit, table | 9 rows; message names HOME |
| 001-15 | 15 | `cli/tests/test_mode.rs` `ac_001_15_refused_home_exits_3_names_home_and_creates_nothing` | CLI (assert_cmd) | modes `1` and `true`; HOME outside child's `TMPDIR`; nothing created |
| 001-15 | 15 | `ac_001_15_guard_is_off_only_for_unset_empty_or_zero_and_allows_home_inside_temp` | CLI, table | `1`+inside, unset, `0`, empty |
| (infra) | - | `testkit/tests/fake_fs.rs` x2, `fixed_clock.rs` x1 | sanity | only non-trivial behavior of the fakes (final-link semantics, ELOOP, device inheritance, civil-date oracle) |

AC-001-16 is covered by devops (build gates, `scripts/check-lint-sample.sh`); not repeated.
46 tests total (43 spec tests + 3 fake sanity). 27 carry `safety` in their path/name.
The testkit `fixed_clock` oracle test gained 2100-03-01 and 2400-02-29 reference values (from Python `calendar.timegm`).

## 2. API the developer must implement (signatures are the contract; bodies are stubs today)

```rust
// cleaner-core::ports
pub enum FileKind { File, Dir, Symlink, Other }
pub struct Metadata { pub kind: FileKind, pub dev: u64 }
pub trait Fs { fn lstat(&self, path: &Path) -> io::Result<Metadata>; }       // read-only by construction
pub trait Clock: Send + Sync { fn now(&self) -> SystemTime; }
pub struct RunId(String);  // new(..), as_str()
pub trait RunIds { fn next_run_id(&self) -> RunId; }
pub trait LogStore { fn list(&self) -> io::Result<Vec<String>>; fn remove(&self, name: &str) -> io::Result<()>; } // names only

// cleaner-core::safety
pub struct HomeDir; HomeDir::new(impl Into<PathBuf>); .path()
pub enum DeniedKind { NotAbsolute, Traversal, DenyListed, AncestorOfDenied, OutsideRoot, SymlinkEscape, CrossDevice, Io }
pub struct Denied { pub kind: DeniedKind, pub path: PathBuf }               // path = refused argument as passed
pub struct SafePath;  .path() -> &Path (normalized), .is_symlink() -> bool, .exists() -> bool
                      // exists()==false only for an absent root from admit_root; always true from admit
pub fn normalize(&Path) -> PathBuf;
SafetyGuard::new(&HomeDir); .with_extra_denied(impl IntoIterator<Item = PathBuf>) -> Self;
  .admit(&self, &dyn Fs, root: &Path, candidate: &Path) -> Result<SafePath, Denied>;
  .admit_root(&self, &dyn Fs, root: &Path) -> Result<SafePath, Denied>;
  //   absent root (lstat NotFound) => Ok{exists=false} AFTER the lexical checks; any other Fs error => Io

// cleaner-core::audit
pub enum Record { RunStart{argv,rule_ids,version,home}, ScanResult{rule_id,status,bytes,items}, Skipped{path,reason}, RunEnd{exit_code,interrupted} }
pub trait AuditSink: Send { fn write_line(&mut self, line: &str) -> Result<(), AuditError>; }
pub enum AuditError { Unavailable{reason}, Io{reason}, Decode{reason} }
AuditLog::new(Box<dyn AuditSink>, Arc<dyn Clock>, RunId); .record(&mut self, &Record) -> Result<(), AuditError>;
pub fn decode_line(&str) -> Result<DecodedRecord{schema,ts,run_id,seq,record}, AuditError>;
pub fn audit_file_name(SystemTime) -> String;
pub fn prune(&dyn LogStore, &dyn Clock, retain_days: u32) -> Result<Vec<String>, AuditError>;

// AC-001-17 (behavior only, NO signature change): deny-list and ancestor comparison use a folded key per component
//   (Unicode case-fold + NFC) for built-in AND extra entries; containment (`OutsideRoot`) stays exact; `SafePath.path()`
//   keeps the caller's spelling (suggested; NOT asserted by any test). Expected new dep: `unicode-normalization` (+ a case fold).
// AC-001-18 (behavior only): `normalize` additionally rewrites a LEADING `/var` `/etc` `/tmp` component to `/private/<it>`
//   after stripping the firmlink prefix; idempotent; `admit_root` docs must say callers pass canonicalized roots.

// cleaner-core::testmode
pub fn is_enabled(value: Option<&OsStr>) -> bool;   // NEW: OFF only for None, "" or exactly "0"; everything else ON
pub fn check(test_mode: bool, home: &Path, temp_dir: &Path) -> Result<(), TestModeViolation{home,temp_dir}>; // unchanged

// cleaner-macos
RealFs: Fs;  FileAuditSink::open(dir: &Path, clock: &dyn Clock) -> Result<Self, AuditError>: AuditSink;
FileLogStore::new(dir): LogStore;

// cleaner-cli (composition root, no new public API needed): in main(), BEFORE argument parsing:
//   read CLEANER_TEST_MODE (as OsStr) -> testmode::is_enabled; HOME, std::env::temp_dir(); canonicalize both
//   paths; core::testmode::check(enabled, ..); on Err print to stderr (names HOME) and exit 3.
```

## 3. Stub inventory (replace every one; all are marked `STUB`)
core: `safety::{normalize, SafetyGuard::admit, admit_root (also: absent-root handling, `exists`), with_extra_denied}`,
`testmode::{is_enabled (stub = old fail-open `== "1"`), check}` (+ `TestModeViolation`'s `Display` omits HOME on purpose), `audit::{AuditLog::record, decode_line, audit_file_name, prune}`.
macos: `RealFs::lstat`, `FileAuditSink::{open, write_line}`, `FileLogStore::{list, remove}`.
cli: `main()` is still empty (no stub needed). Types, traits and the whole testkit are real.

## 4. Dependencies (workspace, versions verified with `cargo search` on 2026-11-06; `cargo deny check` passes)
| crate | where | why |
|-------|-------|-----|
| serde 1.0.229 (derive) | core | record (de)serialization for the JSONL contract (developer's encoder) |
| serde_json 1.0.154 | core (+ used by tests as parse oracle) | JSON lines |
| base64 0.23.1 | core (+ tests as independent oracle) | `path_b64` (AC-001-13); spec says "vetted crate" |
| thiserror 2.0.21 | core | `Denied`, `AuditError`, `TestModeViolation` error types |
| tempfile 3.27.0 | macos, cli (dev) | INV-15 temp dirs for real-adapter and CLI tests |
| assert_cmd 2.2.2, predicates 3.1.4 | cli (dev) | CLI exit-code/stderr assertions with env control |
| proptest 1.12.0 | core (dev) | AC-001-3 explicitly asks for a property; the only use |
Deliberately **not** added: a ULID/UUID crate (no 001 AC needs a production `RunIds`; the trait + testkit
`SequentialRunIds` suffice; add `ulid` in spec 002 with one format test), `insta`, `serial_test`, `trybuild`.

## 5. Ambiguities resolved by the tester (orchestrator: please ratify or amend the spec)
- **A1 Verdict precedence**: syntax (NotAbsolute, Traversal) -> deny list (DenyListed, AncestorOfDenied) ->
  containment (OutsideRoot) -> fs checks (SymlinkEscape, CrossDevice, Io). AC-001-2 requires `/` -> AncestorOfDenied
  although no root contains it, which forces deny-before-containment.
- **A2 Lexical verdicts do no `Fs` access** (reading AC-001-1 "must never touch the filesystem for this verdict beyond
  path resolution"); asserted by `FakeFs::calls()`.
- **A3 `admit` does not validate the root's deny status; `admit_root` does** (deny + ancestor + symlink + absolute). Needed
  so AC-001-1 rows with a root such as `/Users/u` can exist, and for spec 002 AC-002-11.
- **A4 Any symlink among the parent components between root and candidate is `SymlinkEscape`, whatever its target**
  (including a link that points back inside the root, loops, and cycles). Rationale: plan and action would otherwise name
  different files. The guard walks root -> candidate with `lstat` per prefix; it never needs `canonicalize` (the `Fs` port
  has no `canonicalize`/`read_link`: nothing in 001 needs them; the suggested ones were dropped as speculative).
- **A5 `Denied.path` is the refused argument exactly as passed** (candidate; root for `admit_root`).
- **A6 `SafePath.path()` is the normalized spelling** (`//`, `/./`, trailing `/`, firmlink prefix removed); `normalize`
  strips the firmlink prefix *repeatedly* (required for idempotence on `/System/Volumes/Data/System/Volumes/Data/..`)
  after collapsing `.`/`//`.
- **A7 Timestamp format**: `YYYY-MM-DDTHH:MM:SSZ` (whole seconds, `Z`); base64 is the STANDARD alphabet **with padding**.
- **A8 `seq` is not consumed by a failed write** ("no gaps").
- **A9 `prune` boundary**: a file exactly `retain_days` old is kept; only names `audit-YYYY-MM-DD.jsonl` with a valid
  calendar date are candidates; "newest" = greatest date among those; returns removed names ascending.
- **A10 Log sink**: `FileAuditSink::open` creates dir (+missing parents, leaf `0700`) **and the day file (`0600`) at open**; the
  day is fixed at open (no mid-run rollover). `AuditSink::write_line(&mut self, &str)`: the sink appends `\n`.
  `AuditLog` (core) owns `schema/ts/run_id/seq` stamping.
- **A11 `FileLogStore::remove` refuses non-plain names with `InvalidInput`** (defense in depth under the core filter).
- **A12 Test mode**: `home == temp_dir` is a violation (strictly inside); `..`/relative homes are violations; the CLI canonicalizes
  `HOME` and `temp_dir()` before calling `check` (so macOS `/var` -> `/private/var` works); the guard runs before argument
  parsing, so even `--version` is refused; the guard is ON for any value except unset/empty/`0` (amended, section 8).
- **A13 Nonexistent candidate => `Io`** (fail closed; the executor's "vanished" handling is phase 2).

## 6. Not tested on purpose
- "No API to remove/override a built-in deny entry" (AC-001-8, compile-level): reviewed by API surface (`with_extra_denied` is the only
  deny-list mutator); a compile-fail test would pass for unrelated errors.
- `DeniedKind`/`Denied` Display text, serde derives, getters, `HomeDir::new`, the `ulid` production `RunIds`.
- `/usr/local` exception in INV-06 ("except `/usr/local` rule-targeted subpaths"): wording is ambiguous and no phase-1 rule needs it.
- `fsync` (INV-11 requires it for destructive tiers only), tightening the mode of a pre-existing log directory, day rollover mid-run.
- `with_extra_denied` with relative/non-normalized paths; `prune` when `remove` fails; `HOME` unset/non-existent in test mode; `admit_root` on a root whose *ancestor* is a regular file (`ENOTDIR`, treated like any non-`NotFound` error by the rule "other errors are Io", untested).
- Long-path (> `PATH_MAX`) handling beyond the injected `ENAMETOOLONG` row (kernel behavior; guard just fails closed).
- Mutation testing (`cargo mutants`) and coverage: run after green, per the skill.

## 6b. Added in the developer-review round (AC-001-17, AC-001-18, mutation survivors)
- Folded matching is pinned only through `admit`/deny verdicts (not through a public fold function), so the developer is free to choose the
  fold implementation. Full Unicode case folding beyond the tested rows (`\u{c9}`/`\u{e9}`, ASCII) is not exhaustively tested (no `ss`/`\u{df}`
  special-casing): over-blocking is acceptable by the spec, under-blocking of those rows is what is pinned.
- Aliasing of `Users/u` *home* components in a `SafePath` is not rewritten: the admitted path keeps the caller's case (tests only assert
  verdicts for aliased spellings; the `/private` rewrite IS asserted on `SafePath.path()` because AC-001-18 says `normalize` rewrites).
- Mutation run on `audit.rs` after the new rows (`cargo mutants -p cleaner-core --file crates/cleaner-core/src/audit.rs --timeout 60 -j 2 --test-tool nextest -- -E 'binary(audit_log) or binary(audit_retention)'`, via `scripts/with-scratch-home.sh`): 162 mutants, 159 caught, 2 unviable, 1 missed (the trivial `Debug for AuditLog::fmt` -> `Ok(Default::default())`, deliberately not tested).

## 7. Open issues for the orchestrator
1. The CLI refusal test uses `--version` because no other subcommand exists yet; re-point it (or add `scan`) in spec 002 (AC-002-19).
2. `/usr/local` carve-out is deferred by the spec (all of `/usr` denied in phase 1): no test, by design.
(Former items 1-4 and 6 -- fail-open env value, absent roots, `/usr/local`, CI `--no-tests`, scratch HOME -- are resolved by the
amendments / orchestrator changes.)

## 8. Amendments applied (orchestrator, 2026-11-06)
- **AC-001-15 fail-closed**: guard OFF only for unset / empty / exactly `0`; any other value (`1`, `true`, `yes`, `foo`, `00`, ` 0`,
  non-UTF-8) is ON. `check` keeps its pure signature `(bool, &Path, &Path)`; the env interpretation is the new pure helper
  `testmode::is_enabled(Option<&OsStr>) -> bool`, tested by one table, and the CLI tests prove wiring (`true` must now exit 3;
  unset/`0`/empty must not). The old `true`-disables row was removed from the CLI inert table.
- **`admit_root` on an absent root**: `Ok` with `SafePath::exists() == false` (new accessor; `admit` always returns `exists()==true`),
  after the lexical/deny/ancestor/symlink checks; any other `Fs` error (e.g. EACCES on the root or its parent) is `Io`. A *missing
  candidate* is still `Io` (A13). Tests added: absent root admitted with `exists=false`; absent denied/ancestor/relative roots still
  refused with zero `Fs` calls. The AC-001-10 table keeps `admit_root` EACCES -> `Io` and gains "missing root + EACCES on its parent -> `Io`"
  (no pre-existing `admit_root`-missing-root row existed to flip).
