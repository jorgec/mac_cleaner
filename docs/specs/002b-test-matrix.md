# 002b - Test matrix (TDD red phase, ADAPTERS + CLI half of spec 002)
Companion to `docs/specs/002-purgeable-space-scan.md` and `docs/specs/002a-test-matrix.md` (not part of the approved spec text).
Owner: tester. Binding: `testing-policy.md`, `safety-invariants.md`. Status: **RED** (adapters and CLI behavior are stubbed on purpose,
see section 4). Slice 002a (the core: scan, rules, volume math, snapshots parser, report model) is done; section 8 lists the 002a fixups
that came with this slice.

Run: `scripts/with-scratch-home.sh cargo nextest run --workspace --locked` · safety gate: `-E 'test(safety)'` · docs gate:
`scripts/check-test-docs.sh`. Per-function worksheets live in each test file's module header. Opt-in oracle test (needs `/usr/bin/swift`, ~20 s):
`scripts/with-scratch-home.sh cargo nextest run -p cleaner-macos --run-ignored ignored-only -E 'test(swift_oracle)'`.

## 1. AC -> tests

Level legend: **adapter** = real syscalls/processes on a `tempfile` dir (macOS-only crate); **lib** = pure function of `cleaner-cli`'s new library half;
**binary** = the built `cleaner` under `assert_cmd` with `HOME`/`TMPDIR` in a temp dir, `CLEANER_TEST_MODE=1`, cleared environment.

| AC | INV | Test (file :: name) | Level | Notes |
|----|-----|---------------------|-------|-------|
| 002-5 | 07,08 | `macos/tests/real_fs_read_dir.rs` `safety::ac_002_5_read_dir_reports_each_entry_itself_and_never_follows_links` | adapter | file, hidden file, dir, live/dangling/looping symlink, unix socket (`Other`); flat, no `.`/`..`, nothing from the link target |
| 002-7 | 09 | `safety::ac_002_7_read_dir_and_lstat_surface_raw_os_errors_for_missing_nondir_and_locked` | adapter | ENOENT -> `NotFound`, ENOTDIR (20), `chmod 000` dir -> EACCES (13) never `Ok(vec![])`; `lstat` of the locked dir works, of its child is EACCES; Drop guard restores perms; self-skips as root |
| 002-16 | 16 | `ac_002_16_read_dir_returns_names_byte_for_byte_including_hostile_ones` | adapter | space, `\n`, leading `-`, NFD, emoji; non-UTF-8 `0xFF` name is **conditional**: APFS refuses it with EILSEQ (92), the test then asserts exactly that |
| 002-4 | 12 | `ac_002_4_lstat_reports_size_blocks_links_identity_and_mtime_of_the_inode_itself` | adapter | len, mtime (set explicitly), nlink 2 on a hardlink, shared `(dev,ino)`, empty = 0 blocks, sparse `blocks*512 < len`, symlink describes the link (len = target path length) |
| 002-21 | 10 | `macos/tests/real_runner.rs` `safety::safety_ac_002_21_args_are_an_array_and_never_interpreted_by_a_shell` | adapter | `/bin/echo` with `;touch MARKER`, `$HOME`, `` `id` ``, `$(id)`, `*`, `a b`: output verbatim, marker absent |
| 002-21 | 13 | `safety::safety_ac_002_21_timeout_kills_and_reaps_the_child` | adapter | script records its pid then `exec sleep 60`, 1.5 s timeout: `TimedOut`, took >= timeout and < 30 s, pid gone per `kill -0` (so killed **and** waited for) |
| 002-21 | - | `ac_002_21_exit_status_and_both_streams_are_reported_not_turned_into_errors` | adapter, table (3) | `/bin/echo`, `/usr/bin/false` (exit 1 is `Ok`), script with stdout `out` / stderr `err` / exit 3 |
| 002-21 | 13 | `ac_002_21_a_missing_program_is_not_found_and_a_non_executable_file_is_failed` | adapter | `NotFound` vs `Failed` |
| 002-21 | - | `ac_002_21_large_output_on_both_streams_is_captured_without_deadlock` | adapter | 1 MiB on stderr first then 1 MiB on stdout: a sequential reader deadlocks |
| 002-3 | - | `macos/tests/real_volume.rs` `ac_002_3_volume_adapter_describes_the_volume_holding_the_path` | adapter | dir, nested dir, file: total >= 1 GiB, available <= total, 4 numbers not all equal, `mount_point` on the same `st_dev` (NOT a lexical ancestor: firmlinks), `purgeable(&caps).bytes <= total`, same volume for all three |
| 002-2 | 13 | `ac_002_2_volume_adapter_fails_with_typed_errors_and_never_panics_or_reports_zero` | adapter | missing -> `NotFound{path}`; inside `chmod 000` dir -> `PermissionDenied`; empty path, interior NUL, non-UTF-8 -> `Err` |
| 002-3 | - | `ac_002_3_volume_adapter_agrees_with_the_swift_oracle_within_1_mib` | adapter, **`#[ignore = "requires-swift-oracle"]`** | all four numbers within 1 MiB of `tests/oracle/volume_oracle.swift` (ADR 0002). Run once manually, see header |
| 002-17 | 11 | `macos/tests/system_clock.rs` `inv_11_system_clock_is_the_current_time` | adapter | within 1 s of the OS clock (kills a constant/epoch clock) |
| 002-17 | 11 | `cli/tests/run_ids.rs` `ac_002_17_run_ids_are_26_char_crockford_unique_and_strictly_increasing` | lib | 1000 ids in a loop: 26 chars of `0-9A-HJKMNP-TV-Z`, each strictly greater than the previous |
| 002-14 | 02 | `cli/tests/select.rs` `ac_002_14_selectors_narrow_in_table_order_and_reject_unknown_or_disjoint_combinations` | lib, table (9) | none -> 12 in table order; out-of-order+repeated ids -> table order; tier rows; id+tier intersection; disjoint -> `NoMatch`; unknown / case-different id -> `UnknownRule` (message names the id and lists all 12); unknown beats valid |
| 002-7 | 09 | `cli/tests/terminal_app.rs` `ac_002_7_terminal_app_is_named_from_term_program_with_a_generic_fallback` | lib, table (8) | `Apple_Terminal`->Terminal, `iTerm.app`->iTerm, `vscode`, `ghostty`, `WezTerm`; unset / empty / hostile value -> `your terminal app` (never echoed) |
| 002-16 | - | `cli/tests/render.rs` `ac_002_16_format_bytes_uses_base_10_units_with_one_decimal_and_rolls_over` | lib, table (11) | 0, 1, 999, 1000, 1500, 999 949, 999 951 (rollover to `1.0 MB`), spec example values, 10^15, `u64::MAX` |
| 002-7 | 09 | `ac_002_7_permission_hint_appears_once_and_only_for_permission_denied` | lib, table (4) | none / one rule / two rules (3 entries) / io_error+cross_device+refused only; one line naming the app and `Full Disk Access` |
| 002-16 | 02,12 | `ac_002_16_human_report_shows_volume_purgeable_tiers_hint_and_audit_and_never_selects` | lib | the spec's example report: tokens of the Volume, Purgeable (`4.2 GB`, `macOS`, `not added`), `Local snapshots: 0`, tier lines with rule breakdown, one hint, `Audit log:` line with path + run id; no ESC; no `recommend`; `selected` only inside `nothing selected` |
| 002-2 | 13 | `ac_002_2_human_report_says_unknown_never_zero_when_volume_or_snapshots_are_unknown` | lib | `Purgeable` line has `unknown` and **no digit**; snapshots line `unknown`; tier lines still there |
| 002-18/17 | 11,13 | `ac_002_18_human_report_flags_incomplete_runs_and_an_unavailable_audit_log` | lib, 2 rows | `incomplete` iff interrupted; `Audit ... unavailable` when no log |
| 002-19 | 15 | `cli/tests/scan_cli.rs` `safety_ac_002_19_scan_obeys_the_test_mode_guard_before_anything_else` | binary, 4 command lines | HOME outside temp: `scan`, `scan --json`, `scan --rule no-such-rule`, `scan --tier bogus` all exit **3** (guard beats usage errors), stderr names HOME, stdout empty, nothing created. **Green on the stubs by design** (the guard exists since 001): it pins the ordering |
| 002-19 | 15 | `safety_ac_002_19_test_seams_are_refused_outside_test_mode` | binary, 2 modes x 2 seams | `CLEANER_TMUTIL` / `CLEANER_TEST_VOLUME` with test mode unset or `0`: exit 3, names the variable, nothing created, the override script never ran |
| 002-14 | - | `ac_002_14_invalid_selectors_exit_2_list_valid_values_and_create_nothing` | binary, 4 rows | `--rule nope` (all 12 ids listed), `--rule USER-CACHES`, `--tier bogus` (lists `safe`, `caution`, `report-only`), disjoint selectors: exit 2, stdout empty, **HOME still empty (no log dir)** |
| 002-14 | 02 | `ac_002_14_selectors_limit_the_scan_and_no_selectors_scans_all_without_selecting` | binary, 3 rows | none -> 12 rules; `--rule trash --rule user-caches --rule trash` -> `[user-caches, trash]`; `--tier report-only` -> `[ios-backups]`; JSON never contains `recommend`/`select` |
| 002-13 | - | `ac_002_13_top_flag_and_its_default_limit_the_children_listed` | binary, 3 rows | default 5, `--top 2`, `--top 0`; descending, bytes = independent `st_blocks*512` |
| 002-16/3/21 | 12,13 | `ac_002_16_json_mode_prints_only_scan_1_json_with_real_volume_snapshots_and_sizes` | binary, **real volume adapter** | stdout is exactly one JSON doc, stderr empty, exit 0; `schema`, 26-char run id equal to the log's, `home` as given; volume sanity + mount on HOME's device + `purgeable == clamp(important-available,0,total)`; 2 snapshots (one dated, one `null`), `snapshots_unparsed 1`; own audit log not counted in `user-logs` |
| 002-16/3 | - | `ac_002_16_human_report_is_printed_on_stdout_from_live_values_without_ansi_off_a_tty` | binary, 2 rows (`NO_COLOR` unset / `1`) | exit 0, stderr empty, `Volume ... total 494.4 GB`, `Purgeable ... 4.2 GB`, `Safe ... user-caches <bytes>`, no ESC byte on either stream |
| 002-17 | 01,11 | `ac_002_17_scan_writes_one_gap_free_audit_run_prints_its_path_and_changes_nothing` | binary | `run_start` (argv tail, `rule_ids`, home) .. 2 `scan_result` .. `run_end(0,false)`, `seq == 1..n`, one run id; stdout `Audit log:` path + `run <id>`; **old `audit-2000-01-01.jsonl` untouched (no pruning)**; tree fingerprint (kind, mode, size, mtime) outside the log dir identical |
| 002-2 | 13 | `ac_002_2_a_failed_volume_query_is_unknown_not_zero_exit_4_and_the_scan_continues` | binary (`CLEANER_TEST_VOLUME=fail`), 2 modes | JSON `purgeable/total/available null`, `volume_error "query_failed"`, rule bytes still counted, exit 4; human `Purgeable` line `unknown`, no digit |
| 002-21 | 10,13 | `ac_002_21_tmutil_arguments_and_failures_surface_through_the_binary` | binary, 3 rows | fake records its args == `listlocalsnapshots`, `/`; exit 7 -> `snapshots null` + `nonzero_exit` + exit 4; missing -> `tool_missing`; rules still scanned |
| 002-7 | 09,10 | `safety_ac_002_7_an_unreadable_directory_is_skipped_logged_hinted_once_and_exits_4` | binary (real `RealFs` with a `chmod 000` dir), human + JSON | exit 4, `partial`, bytes = only the readable file, `skipped_by_reason.permission_denied 1`, audit `skipped{locked dir, permission_denied}`, ONE `Full Disk Access` line naming `iTerm` (`TERM_PROGRAM=iTerm.app`): stdout in human mode, **stderr in `--json` mode** (stdout stays pure JSON) |
| 002-17 | 13 | `ac_002_17_an_unavailable_audit_log_warns_on_stderr_exits_4_and_the_scan_still_runs` | binary, 2 modes | `Library/Logs` is a regular file: exit 4, stderr mentions `audit`, JSON `audit_unavailable true` with real bytes, human report still printed, nothing created or changed |
| 002-18 | 11 | `ac_002_18_sigint_stops_the_scan_exit_130_and_run_end_records_the_interruption` | binary, background process | see section 3.3 |
| 002-7 (root) | 09 | core `scan_walk.rs` `safety::ac_002_7_root_permission_error_is_partial_other_root_errors_and_verdicts_stay_refused` | scan | the 002a fixup (**intentionally red**), section 8 |

34 new tests that run by default (33 spec + the core fixup) + 1 ignored oracle. 8 of them carry `safety` in module or test name (`-E 'test(safety)'` now selects 48 tests workspace-wide: 40 before + these 8; 7 are red, `safety_ac_002_19_scan_obeys_the_test_mode_guard_before_anything_else` is green by design).
Covered elsewhere (not repeated): exit-code policy table, `scan/1` key order, notes, `path_b64`, hardlinks/sparse/saturation arithmetic, cancellation granularity,
10 000-level depth (all `cleaner-core`, 002a); the `--version` guard (001 `test_mode.rs`, unchanged and still green).

## 2. API the developer must implement (types/signatures are real; bodies marked `STUB` are the work)

```rust
// cleaner-macos
pub struct RealFs;      impl Fs { fn lstat /*REAL, fills ino, blocks, len, mtime, nlink*/; fn read_dir /*STUB: Err(Unsupported)*/ }
pub struct RealRunner;  impl CommandRunner   // STUB: Err(Failed). Contract in its rustdoc: Command::new(program).args(args) (no shell), stdin null, drain stdout+stderr
                        //   concurrently, non-zero exit = Ok, spawn NotFound -> NotFound, other spawn error -> Failed, timeout -> kill + wait + TimedOut
pub struct RealVolume;  impl VolumeCapacity  // STUB: Err(QueryFailed). objc2-foundation NSURL resource values; NotFound{path} / PermissionDenied / QueryFailed
pub struct SystemClock; impl Clock           // STUB: UNIX_EPOCH
// cleaner-cli (library half, NEW: crates/cleaner-cli/src/lib.rs; the bin is main.rs)
pub const VERSION: &str;                                                        // REAL ("<ver> (<sha> <triple>)")
args::{Cli, Command::Scan(ScanArgs), ScanArgs{rules: Vec<String>, tier: Option<TierArg>, top: usize, json: bool}, TierArg}   // REAL clap derive; TierArg::tier() -> core Tier
select::select_rules(all: Vec<Rule>, ids: &[String], tier: Option<Tier>) -> Result<Vec<Rule>, SelectError>   // STUB: returns all
select::SelectError::{UnknownRule{id, valid}, NoMatch}  + Display                // Display is a STUB ("STUB"); must name the id and list every valid id
ids::UlidRunIds::{new()} impl RunIds                                              // STUB: constant "STUB"
fda::terminal_app(Option<&str>) -> String                                         // STUB: ""
render::format_bytes(u64) -> String                                               // STUB: raw number
render::permission_hint(&ScanReport, terminal_app: &str) -> Option<String>        // STUB: None
render::human(&ScanReport, &HumanContext{audit_log: Option<PathBuf>, terminal_app: String}) -> String   // STUB: ""
// main.rs (composition root): guard FIRST (real, unchanged), then clap; `Command::Scan(_)` is a STUB returning exit 0 and printing nothing.
```
Composition the developer must write in `main.rs` (every item has a test): test-mode guard first; seam variables refused when test mode is off; `Cli::parse()`;
`select_rules(builtin(), &args.rules, args.tier.map(TierArg::tier))` (`Err` -> stderr, exit 2); `HOME` from the environment as given (not canonicalized);
`SystemClock`, `UlidRunIds`, `RealFs`; volume = `RealVolume` or the test seam; runner = `RealRunner` or the seam wrapper (program `/usr/bin/tmutil` replaced by `CLEANER_TMUTIL`);
`FileAuditSink::open($HOME/Library/Logs/mac-cleaner, clock)` -> `Some(AuditLog)` or `None` + stderr warning; install the SIGINT handler **before `run_scan`** (it must
already be active while `tmutil` runs: the SIGINT test depends on it) setting the `CancelToken`; `run_scan`; print JSON (pretty or compact, one document + newline) or `human(..)`;
the permission hint on stdout (inside `human`) or, with `--json`, on stderr; audit-unavailable warning on stderr; exit `report.exit_code()` (0/4/130).
The audit path shown is `$HOME/Library/Logs/mac-cleaner/<audit_file_name(clock.now())>` with `$HOME` as given. No pruning at the end of a scan (section 6, A3).

## 3. Design decisions (the hermetic seams, the SIGINT test, the lib/bin split)

### 3.1 Test-only seams (justification)
The real `tmutil` must never run from a test and a real volume query only where stated. Two environment variables, **honored only when the INV-15 guard is on**
(`CLEANER_TEST_MODE` on and `HOME` inside the temp dir), replace the two process-external adapters:
* `CLEANER_TMUTIL=<path>`: the program run instead of `/usr/bin/tmutil` (arguments unchanged: `listlocalsnapshots /`). Tests point it at a tiny `/bin/sh` script with canned output.
* `CLEANER_TEST_VOLUME=fail | <total>:<available>:<important>` (decimal bytes): replaces the Foundation query with a failure (`QueryFailed`, code `query_failed`) or fixed numbers.
  The fixed numbers are ADR 0002's (494 384 795 648 / 365 789 609 984 / 369 982 967 776 -> purgeable 4 193 357 792 = `4.2 GB`).
**Refused, not ignored, outside test mode**: with test mode off, a set seam variable makes the process exit **3** naming the variable, before anything is created or run
(`safety_ac_002_19_test_seams_are_refused_outside_test_mode`). The brief asked for "ignored when test mode is off"; ignoring would force that test to run the real `tmutil`
(the only way to observe "ignored" at the process level), which the brief forbids. Refusing is observable without side effects, is fail-closed (INV-13: a stray variable in a
user's shell cannot silently replace a program or fake a result), and fits exit 3 "an invariant tripped". The stronger property "the override script is never executed" is asserted.
The only test that uses the real volume adapter is `ac_002_16_json_mode...` (queries the temp `HOME`, read-only).

### 3.2 Library half for the CLI crate
`cleaner-cli` gains `src/lib.rs` (`args`, `select`, `render`, `fda`, `ids`) so renderer, selectors, units, hint and ids are unit-tested at the lowest level (policy: "lowest level that sees
the behavior"); `main.rs` stays the composition root and `build.rs` is untouched. Only wiring is tested through the binary (13 binary tests, ~50 ms each).

### 3.3 SIGINT test: deterministic, no timing assumptions
The canned `tmutil` creates `started`, then polls for `release`. The test starts `cleaner scan --json`, waits (bounded 15 s) until `started` exists - at that moment the scan is provably
running and has not walked a rule yet - sends `kill -INT <pid>` to the cleaner only, then creates `release`. The scan resumes with the token already set (spec decision D18/D19: a
pre-cancelled run lists nothing) and must report every rule `interrupted`, write `run_end{130, interrupted}` and exit 130. This tests the handler wiring, the exit code and the audit trail,
not "mid-walk" timing (mid-walk granularity is core-tested with the token). A guard kills the child if an assertion fails. Cost on a correct build: ~0.2 s; red on the stub: 15 s (bounded wait).
Limit worth knowing: the signal arrives while the runner is inside `tmutil`'s wait; the adapter must not let the signal (or the handler thread) break that wait.

## 4. Stub inventory (all marked `STUB`; replace every one)
macos: `RealFs::read_dir`, `RealRunner::run`, `RealVolume::query`, `SystemClock::now`. cli: `select::select_rules` (+ `SelectError` Display), `ids::UlidRunIds::next_run_id`,
`fda::terminal_app`, `render::{format_bytes, permission_hint, human}`, and the `Command::Scan` arm of `main`. core: nothing new (the 002a fixup test needs a change in `scan.rs`, section 8).
Real code added by the tester (reviewed, not stubs): `args.rs` (clap derive), `lib.rs`, the `VERSION` const, manifests, test infrastructure (`tests/common/mod.rs`, `tests/oracle/volume_oracle.swift`).

## 5. Dependencies added (all verified with `cargo search`, `cargo deny check` passes: advisories, bans, licenses, sources)
| Crate | Version | Where | Why | Cost |
|-------|---------|-------|-----|------|
| `clap` | 4.6.7, `default-features = false`, features `std derive help usage error-context suggestions` | cli | the derive CLI the spec asks for; no `color`/`wrap_help`/`env` features, so no ANSI from clap and few transitive crates | `clap_builder`, `clap_derive`, `clap_lex`, `strsim`, `heck` |
| `ulid` | 3.0.0, `default-features = false`, feature `std` | cli | production `RunIds`; monotonic `Generator` (API: `generate()` returns `Result<Ulid, Overflow>`; use `Overflow::commit_overflow_increment()`) | `rand`/`getrandom`, `web-time` (pass-through on macOS; the wasm-only crates appear only in `Cargo.lock`, not in the macOS build graph) |
| `signal-hook` | 0.4.6 (default features) | cli | SIGINT -> `CancelToken` through the **safe** `iterator::Signals` API (a thread loops `signals.forever()`), so the CLI crate needs no `unsafe`; `ctrlc` would also work | `signal-hook-registry`, `libc` (already present) |
| `objc2` + `objc2-foundation` | 0.6.5 / 0.3.2, `default-features = false`, features `std NSURL NSString NSArray NSDictionary NSError NSValue` (the minimal set that compiles the reference implementation) | macos only | ADR 0002 option A (`NSURL resourceValuesForKeys`); extern statics (`NSURLVolume*Key`) need one `unsafe` block, with `// SAFETY:` and covered by `real_volume.rs` | `objc2-encode`, `bitflags` |
| `serde_json` | workspace (already used by core) | cli | print the report | none new |
`signal-hook`, `objc2*`, `serde_json`, `ulid`, `clap` are declared in the manifests so the lockfile and `cargo deny` are settled; the stubs do not use `objc2*`, `signal-hook`, `ulid` yet.
Dev-dependencies: none added (`serde_json` is now also a normal dependency of the CLI crate and is used by its tests).

## 6. Ambiguities resolved here / needing orchestrator ratification
* **A1 Seams refused outside test mode (exit 3) instead of ignored.** Section 3.1. Ratify or give an alternative that does not run the real `tmutil` from a test.
* **A2 `--rule` + `--tier` = intersection; empty intersection = usage error (exit 2, "no rule matches ..."); unknown id is checked first; ids are case-sensitive; rules are always scanned in table order and deduplicated, never in flag order.**
  Spec only says "limit the scan". Union would also be defensible; intersection never widens a scan.
* **A3 A scan never prunes old audit logs.** The spec says "Writes: audit log only" while spec 001 AC-001-14 defines retention without saying who calls `prune` and when. The test pins "scan does not delete the 2000-01-01 file".
  If retention should run at the end of a scan, that is a spec amendment (it is a deletion; INV-01/INV-04 need a decision).
* **A4 Permission hint routing.** Human mode: one line on stdout inside the report. `--json`: the same single line on stderr (stdout stays pure JSON). Audit-unavailable warning: always stderr.
* **A5 Human layout is pinned by tokens only**: lines starting `Volume`, `Purgeable`, `Local snapshots:`, `Safe`/`Caution`/`Report-only`, `Audit log:`; `unknown` for unknown values; `incomplete` when interrupted;
  `nothing selected` in the heading; units base-10 `B kB MB GB TB PB EB` with one decimal and rollover. Spacing, alignment, colors, the example's `·` separators are free.
* **A6 `home` and the audit path use `$HOME` exactly as given** (no canonicalization): the INV-15 guard canonicalizes only for its own comparison.
* **A7 `TERM_PROGRAM` mapping**: `Apple_Terminal` -> `Terminal`, `iTerm.app` -> `iTerm`, `vscode` -> `Visual Studio Code`, `ghostty` -> `Ghostty`, `WezTerm` -> `WezTerm`, otherwise `your terminal app`
  (unknown values are never echoed: escape-sequence injection through the environment). Extend the table with a row in `terminal_app.rs`.
* **A8 `RealVolume` error classes**: missing path `NotFound{path as queried}`; a path below a `chmod 000` directory `PermissionDenied`; empty / NUL / non-UTF-8 path `Err` (class not pinned, `QueryFailed` expected).
  `mount_point` is checked by `st_dev`, not lexically (firmlinks: `/private/var/..` is on `/System/Volumes/Data`).
* **A9 `RealRunner`**: a child killed by a signal has no `exit_code` in std; the port does not define what it reports and no test pins it (the reference used `-1`). Developer's call; document it.
* **A10 Non-UTF-8 names cannot exist on APFS** (EILSEQ), so the adapter-level class is asserted conditionally. The report-side lossless path (`path_b64`) stays covered by core tests with `FakeFs`.
* **A11 Real-adapter tests are not `#[cfg(target_os = "macos")]`-gated** because `cleaner-macos` is macOS-only by charter and builds nowhere else; the oracle is the only opt-in test.

## 7. Not tested on purpose
* stdin of the child being closed (`Stdio::null()`): nextest runs tests with a null stdin already, so a runner that inherits it is indistinguishable here; stated in the rustdoc of `RealRunner` for the developer.
* `tmutil` timing out through the binary (10 s of wall clock): the adapter kills a hung child (tested with a 1.5 s timeout) and core maps `TimedOut`.
* A signal-killed child's exit code (A9); `--help` text and clap's own parsing; colored output on a TTY (no pty in tests; the spec only forbids ANSI off-TTY).
* Mid-walk SIGINT through the binary (needs timing; the token is core-tested, the handler wiring is tested in the deterministic window).
* The internals of `objc2` (unsafe is confined to one block in `cleaner-macos`; the test is "numbers are right", the oracle checks them against Apple's own).
* `read_dir` of a final symlink (std/opendir behavior; the scanner never lists a link; the `Fs` port documents it).
* A non-root assumption: `chmod 000` scenarios self-skip (print a note) when the test process is root.

## 8. Fixups to 002a delivered with this slice (details in `002a-test-matrix.md` section 9)
(1) parser row `2026-02-28` (kills the `days_in_month` mutant); (2) `top` never lists zero-byte children (D15); (3) **new, intentionally red** root-permission test:
`lstat` of a root failing with EACCES/EPERM -> `partial`, 0 bytes, one `skipped{permission_denied}`, not `refused`; EIO / guard verdicts stay `refused`.
Developer note: `SafetyGuard::admit_root` reports every non-ENOENT `lstat` failure as `DeniedKind::Io` without the errno; the reference fix re-`lstat`s the root in `scan.rs::admit_root` when the verdict is `Io`.

## 9. Validation of the tests themselves (tester, throwaway; the repo keeps stubs only)
A **throwaway reference implementation** of every stub (macos adapters with `objc2-foundation`, the cli library, a full composition root with `signal-hook`, and the ~12-line root-permission change in
`scan.rs`) was written in a scratch copy outside the repo: all **118** default tests were green against it (the 84 old ones, the 002a fixup, and the 33 new ones), and the opt-in Swift-oracle test passed
(adapter within 1 MiB of Foundation as seen by Swift, 18 s). `cargo mutants` (nextest, scratch HOME) on that reference:
* `cleaner-macos` (`read_dir`, `RealRunner`, `SystemClock`, `volume::*`): first run 33 mutants, 7 missed. Three test strengthenings followed (a `PermissionDenied` row, an `ENAMETOOLONG` -> `query_failed` row, and "total >= 1 GiB, four numbers not all equal" for the volume adapter). Re-runs: 0 missed except
  two **equivalent** mutants of the reference, not of the tests: a redundant `empty || contains NUL` pre-check (the following `symlink_metadata` already fails for those paths, observable behavior identical) and the exit code of a signal-killed child (`unwrap_or(-1)` -> `1`; the port leaves it undefined, A9).
* `cleaner-cli` (library + `main.rs`, 70 mutants): 62 caught, 6 unviable, 2 missed - both `n > 0` -> `n >= 0` on a `skipped_by_reason` count in the reference renderer, reachable only with a map entry of 0, which the scanner never produces (equivalent in practice).
* `cleaner-core` `admit_root`/`scan_rule`/`walk_rule` (the root-permission change): 17 mutants, 13 caught, 4 unviable, 0 missed.
The reference is not kept (the repo has stubs only). The developer should re-run mutants on the real code.
Lesson recorded for the developer: **never share `CARGO_TARGET_DIR` between a `cargo mutants` run and normal test runs** (stale mutated artifacts produced phantom failures).

## 10. Hardening round (after 002b went green: 118 tests)
Three new tests (121 total; the first run had 119 green and **2 intentionally red**, the developer has since made all 121 green), one doc/worksheet update per file. Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
`scripts/check-test-docs.sh` (119 test fns), `cargo deny check` all clean.

| # | Item | Test (file :: name) | Level | State | Notes |
|---|------|---------------------|-------|-------|-------|
| H1 | Non-ok rules visible (honesty) | `cli/tests/render.rs` `ac_002_16_human_report_names_every_non_ok_rule_after_the_tiers_and_hides_zero_byte_ok_rules` | lib | **RED** (behavior change) | `known_report` + `docker-data` (refused, `root_refused`, 0 B), `xcode-derived` (interrupted, 0 B), `empty-ok` (ok, 0 B). Each of `docker-data`, `xcode-derived`, `ios-backups` (already in the fixture: partial, `permission_denied`) has a line `<id>: <status>` after the `Report-only` tier line, reasons named where known; no tier line mentions `trash` (absent, 0 B, already in the fixture) or `empty-ok`; no line `trash:`/`empty-ok:`/`user-caches:`/... (ok/absent are never problems). The negative half also kills the surviving mutant `render.rs: r.bytes > 0 -> >= 0` |
| H2 | Audit path shown = path opened | `macos/tests/audit_file.rs` `ac_002_17_sink_reports_the_exact_path_it_opened_fixed_at_open` | adapter | **RED** against the stub | clock fixed at 2026-12-31T23:59:59Z (last second of a day): `path() == <dir>/audit-2026-12-31.jsonl`, the file exists there, and a `write_line` lands in that very file |
| H3 | Runner bounded with a grandchild on the pipes | `macos/tests/real_runner.rs` `safety::safety_ac_002_21_timeout_still_bounds_the_call_when_a_grandchild_holds_the_pipes` | adapter, table (3) | green (existing behavior) | script runs `/bin/sleep 30 &` (rows: `both-pipes`; `stderr-only` = `>/dev/null`; `stdout-only` = `2>/dev/null`) and exits at once; 1.5 s timeout: `Err(TimedOut)`, elapsed `>= 1.5 s` and `< 10 s`; a drop guard kills the stray sleep |

**H1 contract.** After the three tier lines, the human report lists every rule whose status is `refused`, `partial` or `interrupted` as `<rule-id>: <status>` (a line whose first token is `<rule-id>:`), followed on the
same line by its skip reason codes when it has any (`root_refused`, `permission_denied`, ...), whatever its bytes. `ok`/`absent` rules with 0 bytes appear in no tier line and in no problem line. The existing
`(permission denied)` marker in the tier line is unchanged (that test still passes). Wording after the `<id>: <status>` prefix, the order among problem rules, and whether a refused 0-byte rule is
*also* allowed in its tier line are free (tokens only, A5).

**H2 contract and stub.** `FileAuditSink::path(&self) -> &Path` (added to `crates/cleaner-macos/src/lib.rs` as a marked `STUB`, returns `/STUB/audit-path-not-implemented`): the file opened by `open`, i.e.
`dir.join(audit_file_name(clock.now()))` computed once inside `open` (store it in the struct). The composition root (`scan_cmd.rs`) must print `sink.path()` (take it **before** boxing the sink into the `AuditLog`)
instead of recomputing `log_dir.join(audit_file_name(clock.now()))` a second time. No cli-level test was added: `ac_002_17_scan_writes_one_gap_free_audit_run_prints_its_path_and_changes_nothing` already asserts that
the `Audit log:` line contains the path of the one audit file that exists in the fixture HOME, so a second CLI check would add nothing; the midnight straddle itself needs a clock seam the binary does not (and
should not) have, and is covered at the lowest level by H2 (the path is fixed at `open`).

**H3 reasoning (which mutants of the drain loop each row kills; line numbers of `capture`, `lib.rs:277/278`).** The direct child exits at once, so the `try_wait` loop ends and only the "drain threads finished" loop
remains; the grandchild keeps pipe(s) open for 30 s. Row `both-pipes` kills an **unbounded drain** (verified on a scratch copy of the workspace, not the repo, with the deadline check removed from that loop: the test failed after
30.5 s with the elapsed-bound message) and the flipped deadline test `>=` -> `<` (`:278`, returns before the timeout). It does **not** kill `&&` -> `||` at `:277`: with both pipes held neither stream finishes, so the mutated loop
still waits for the deadline (this section previously claimed otherwise; that was wrong, found by cargo-mutants). Rows `stderr-only` / `stdout-only` kill `&&` -> `||` (`:277:34`): one pipe is at EOF as soon as the shell exits, the
mutated loop leaves and `join`s the reader of the other pipe for ~30 s (the elapsed bound fails). Two mirror rows so that dropping either operand or checking a single stream is also seen.
`cargo mutants -p cleaner-macos --file crates/cleaner-macos/src/lib.rs --test-tool nextest --timeout 60 -j 2` (scratch HOME, per-job copies, own output dir): `--re 'lib.rs:27[78]'` 3 of 3 caught; the full file: 40 mutants,
19 caught, 18 unviable, 1 timeout, **2 missed, both equivalent/benign**: `:266:40` `<` -> `<=` (a boundary of one clock instant, unobservable) and `:285:44` `unwrap_or(-1)` -> `1` (the exit code of a signal-killed child, left undefined by
the port, A9); the `:266:25` match-guard -> `true` mutant never times out a hung child, so it hangs and is stopped by the 60 s mutants timeout (the existing hung-child test sees it as a hang, not as an assertion).
On the real code the test takes ~4.7 s (3 x 1.5 s). The orphaned `sleep` is deliberately **not** asserted dead: `RealRunner` kills only its direct child (process groups are outside the contract, worksheet), so the test kills
the sleep itself through a drop guard per row (`/bin/kill <pid>`, allow-listed like the existing liveness probe); no `sleep 30` was left running after the suite or the mutants run.

**H4 Not tested on purpose.** `volume.rs::mount_on_device` (the `st_dev` fallback): unreachable on this machine (`/`, `$HOME` and the Data volume report the same `st_dev`) and slated for removal by the developer. No test
references it (it is private; `real_volume.rs` asserts only the observable `mount_point` on the same `st_dev` as the path, which holds with or without the fallback).

**Red evidence.**
```
FAIL cleaner-cli::render ac_002_16_human_report_names_every_non_ok_rule_after_the_tiers_and_hides_zero_byte_ok_rules
  INV-13: no `docker-data: refused` line in the report:   (tier lines shown: Safe 5.2 GB user-caches.., Caution.., Report-only 0 B ios-backups 0 B (permission denied))
FAIL cleaner-macos::audit_file ac_002_17_sink_reports_the_exact_path_it_opened_fixed_at_open
  left: "/STUB/audit-path-not-implemented"  right: ".../logs/audit-2026-12-31.jsonl"
```
`cargo nextest run --workspace --locked --no-fail-fast`: 121 run, 119 passed, 2 failed (exactly the two above), 1 skipped (the opt-in Swift oracle).

**Ambiguities for ratification.** (a) H1: is `partial` with only `io_error` skips listed (yes: any `partial`), and should `absent`/`ok` rules with skips (e.g. `ok` + `cross_device`) be listed? The test says no: only the three
statuses, and `exit_code()` only counts those three. (b) H1: a `refused` rule with 0 bytes is allowed, not required, in its tier line.
