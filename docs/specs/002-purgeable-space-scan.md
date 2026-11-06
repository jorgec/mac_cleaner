# 002 – Purgeable and reclaimable space scan (`cleaner scan`)
Status: Approved · Owner: orchestrator · Risk tier: Report-only (nothing is deleted or selected)
Depends on: 001, ADR 0002

## Problem / user value
"Where did my disk go, and how much could I get back?" The user's top priority is
**identifying purgeable space**. `cleaner scan` answers, read-only and with a complete audit trail:
1. How much space macOS considers **purgeable** on the volume holding `$HOME` (OS-managed).
2. What can be **named**: local Time Machine snapshots (count/dates), and per-rule **reclaimable**
   bytes in known categories, by tier.
3. What the tool could not see (permissions, unreadable, interrupted), stated honestly.

## Non-goals
Deleting, moving, or selecting anything. Freeing purgeable space. Per-file item selection (phase 3).
Reading file contents. Detecting APFS clones (documented over-count caveat). Scanning outside rule roots.
Scanning ≠ selecting (INV-02): no output field marks anything "recommended" or "selected".

## Concepts
`purgeable = max(0, available_important − available)` (ADR 0002). Reclaimable per rule = sum of
**allocated** bytes (`st_blocks*512`) of regular files/symlinks under the rule's roots that match its
filters, hardlink-deduplicated per `(dev, ino)` across the *whole run*. Logical size reported alongside.

## Built-in rules (data; every root is relative to `$HOME`)
| id | tier | roots | filter / note |
|----|------|-------|---------------|
| `user-caches` | Safe | `Library/Caches` | excludes subtrees claimed by more specific rules (e.g. `homebrew-cache`) |
| `homebrew-cache` | Safe | `Library/Caches/Homebrew` | |
| `user-logs` | Safe | `Library/Logs` | **excludes** `Library/Logs/mac-cleaner` and `Library/Logs/mac-cleaner-dev` (never report our own logs as reclaimable) |
| `trash` | Safe | `.Trash` | |
| `xcode-derived-data` | Safe | `Library/Developer/Xcode/DerivedData` | |
| `cargo-cache` | Safe | `.cargo/registry/cache`, `.cargo/registry/src`, `.cargo/git` | re-downloadable |
| `npm-cache` | Safe | `.npm/_cacache` | |
| `xcode-archives` | Caution | `Library/Developer/Xcode/Archives` | may be the only copy of a shipped build |
| `ios-device-support` | Caution | `Library/Developer/Xcode/iOS DeviceSupport` | |
| `coresimulator` | Caution | `Library/Developer/CoreSimulator/Devices` | |
| `old-downloads` | Caution | `Downloads` | only regular files with `mtime` ≥ 90 days old |
| `ios-backups` | Report-only | `Library/Application Support/MobileSync/Backup` | listed, never deletable; usually needs Full Disk Access |

Every root must be admitted by `SafetyGuard` (AC-002-11). Adding a rule requires its own spec amendment.

## Behavior

### Volume and purgeable
- **AC-002-1 [INV-12,INV-13] Purgeable arithmetic.** Given caps (total T, available A, important I):
  I ≥ A → `purgeable = I − A`; I < A → `purgeable = 0` and `purgeable_clamped = true`; result never
  exceeds T and never underflows (u64, checked). Boundary: I == A → 0 with `purgeable_clamped=false`.
- **AC-002-2 [INV-13] Unknown is not zero.** Given `VolumeCapacity` fails → JSON `purgeable: null`,
  `volume_error: "<kind>"`, human output says "unknown"; rule scanning still runs; exit code 4.
  Must never print or serialize `0` for an unknown value.
- **AC-002-3 Right volume.** The adapter is queried with the injected `$HOME`; the report includes
  `mount_point`, `total`, `available`, `available_important`, `purgeable`.
- **AC-002-21 Local snapshots.** Via `CommandRunner` (`tmutil listlocalsnapshots /`, args array, timeout 10 s,
  no root): parse names `com.apple.TimeMachine.<YYYY-MM-DD-HHMMSS>.local` into `{name, date}`; zero snapshots →
  `[]` (not an error); unparseable lines are kept as `{name, date:null}` and counted in `unparsed`; sizes are
  `bytes: null` (tmutil does not report them) and a note code `snapshot_sizes_unavailable` is emitted;
  tool missing / non-zero exit / timeout → `snapshots: null` + `snapshots_error` and exit code 4.
  The command is invoked read-only; **no** `tmutil delete*`/`thinlocalsnapshots` anywhere.

### Size accounting (per rule, shared walker)
- **AC-002-4 [INV-12] Counting rules.** Allocated = `blocks*512`; logical = `len`. Zero-byte file → 0 bytes,
  1 item. Sparse file → allocated < logical. A hardlinked inode seen twice (same or different rule) counts once,
  attributed to the first rule in rule order, and the second sighting is tallied in `deduped_links`.
  Sums use saturating arithmetic (no overflow panic).
- **AC-002-5 [INV-07] No symlink following.** A symlink to a large directory outside the root contributes
  only the link's own `lstat` allocation; the target is not entered; symlink loops terminate.
- **AC-002-6 [INV-08] Device boundary.** A directory on a different `st_dev` than its root is not descended;
  recorded `skipped{reason:"cross_device"}`.
- **AC-002-7 [INV-09] Unreadable entries.** `EPERM/EACCES` on an entry → `skipped{reason:"permission_denied"}`,
  walk continues, rule status `partial`, exit code 4; human output includes a one-time Full Disk Access hint
  naming the *terminal app* that needs it (not the binary). No retry, no escalation (INV-10).
- **AC-002-8 Vanishing entries.** `ENOENT` for an entry that existed at listing time → counted in `vanished`,
  not an error, does not set `partial`.
- **AC-002-10 Absent roots.** A root that does not exist → rule `status:"absent"`, 0 bytes; not an error; exit 0.
- **AC-002-12 Age filter.** For rules with `min_age`, only files with `mtime <= now − min_age` count
  (exactly-at-threshold **counts**; future mtimes do **not**; `now` from the injected `Clock`).
  Directories are not counted themselves; their eligible files are. atime is never used.
- **AC-002-9 Nested/overlapping roots [INV-12].** A path is claimed by the most specific rule root containing it;
  a parent rule's totals exclude claimed subtrees. Sum of all rules' bytes == bytes of the union of roots
  (no double counting). Component-wise: root `Caches` must not claim `Caches-old`.
- **AC-002-22 Excludes.** Subtrees matching a rule's `excludes` contribute 0 to that rule and are not claimed by it.

### Rules table integrity
- **AC-002-11 [INV-05,INV-06] Table validity.** Over the whole built-in table: ids unique and kebab-case;
  every rule has tier + non-empty `explain`; every root passes `SafetyGuard::admit_root` for a sample home;
  no root equals or contains a deny-listed path; `Report-only` rules have `deletable=false`;
  no two rules have identical roots. (One data-driven test.)

### Reporting
- **AC-002-13 Top children.** Per rule, `top` = up to N (default 5, `--top N`, N=0 allowed) immediate
  children of the roots by allocated bytes, descending, ties broken by path bytes ascending (deterministic).
- **AC-002-16 Output contract.** Human table on stdout (totals per tier, units base-10 GB with exact bytes in JSON;
  no ANSI when `NO_COLOR` set or not a TTY). `--json`: **only** JSON on stdout (schema `scan/1`, stable key order),
  warnings on stderr. Non-UTF-8 paths: `path` lossy + `path_b64` when lossy differs (consistent with AC-001-13).
- **AC-002-20 Honesty notes.** JSON `notes` is an array of stable codes, always including
  `purgeable_is_os_managed`, `purgeable_and_reclaimable_not_additive`, `trash_move_frees_nothing_until_emptied`,
  `clone_overcount_possible` (plus `snapshot_sizes_unavailable` when applicable). Tests assert codes, not prose.
- **AC-002-14 Selectors.** `--rule <id>` (repeatable) and `--tier <safe|caution|report-only>` limit the scan.
  Unknown id/tier → exit 2 listing valid values, nothing scanned, no log created. No selectors = all rules
  (permitted because scanning is read-only; nothing is marked selected).

### Safety and lifecycle
- **AC-002-15 [INV-01] Read-only.** For any fixture tree, a full scan leaves it unchanged (content + mtime hash
  identical) and the `Fs` fake records zero mutating calls. The scan code path has no access to a mutating port.
- **AC-002-17 [INV-11] Audit.** Each run writes: `run_start` (argv, rule ids, version, home), one `scan_result`
  per rule (status, bytes, items, skipped/vanished/deduped counts), `skipped` records (path, reason; capped at
  1000 per run with the overflow count in the rule's `scan_result`), and `run_end` (exit code, totals, `interrupted`).
  Same `run_id`, `seq` gap-free. If the audit sink is `Unavailable`, the scan still runs, a warning goes to
  stderr, and the exit code is 4 (read-only scan; INV-13 fail-closed applies to mutating phases).
- **AC-002-18 Cancellation.** A cancel token (SIGINT handler sets it) stops the walk within one directory
  entry batch; results so far are reported with `incomplete:true`; `run_end.interrupted=true`; exit code 130.
  Core-level test uses the token directly; one CLI-level test sends SIGINT.
- **AC-002-19 Test-mode guard.** `scan` honors AC-001-15 before doing anything else.

## Ratified decisions (orchestrator, 2026-11-07; full list D1–D14 in `002a-test-matrix.md`)
- **Root admission at scan time:** each rule root must be relative and pass `SafetyGuard::admit_root`; otherwise the
  rule is `refused` (0 bytes, never listed, one `skipped{reason:"root_refused"}`, exit 4). Fail-closed.
- **Vocabulary:** rule status `ok | partial | absent | refused | interrupted` (`absent` = no root exists);
  skip reasons `permission_denied | cross_device | io_error | root_refused | …`.
- **`cross_device` is by design, not a failure:** it is recorded and counted but does **not** make a rule
  `partial` and does **not** by itself change the exit code. (`permission_denied`/`io_error`/`root_refused`,
  unknown volume/snapshots, unavailable audit log do → exit 4.)
- **Skip-record cap** is 1000 per run, in rule order; the per-rule overflow is `skipped_unlogged`.
- **`purgeable_clamped`** also flags capping at `total`.
- **Age filter** counts regular files only (a symlink under `old-downloads` is not counted).
- **Snapshots:** the `Snapshots for …:` header line is not a snapshot; `date` is local time `YYYY-MM-DDTHH:MM:SS`;
  program is absolute `/usr/bin/tmutil`; failure kinds `tool_missing | nonzero_exit | timeout | spawn_failed`;
  `snapshot_sizes_unavailable` iff ≥1 snapshot listed.
- **JSON `scan/1` shape** is whatever `ac_002_16_json_schema_scan_1_pins_key_names_and_order` pins; changing it
  requires a schema bump (`scan/2`) and an orchestrator decision. `ScanReport::exit_code` lives in core.
- **Audit extension:** `scan_result` gains `logical_bytes, skipped, skipped_unlogged, vanished, deduped_links`;
  `run_end` gains `total_bytes, total_items`.

### Ratified after 002a development (2026-11-07)
- `top` lists only children with **> 0 allocated bytes** attributed to that rule (empty dirs, skipped/unreadable,
  cross-device, claimed-by-other-rule and excluded children are never listed). (D15)
- Any refused root refuses the whole rule (status `refused`, none of its roots walked). (D16)
- The audit sink is switched off after its first failed write: log stays gap-free but short, report sets
  `audit_unavailable`, exit 4. (D17)
- `incomplete`/`interrupted` are set iff some rule ended `interrupted`; a token raised after the last listing leaves
  the run complete. A pre-cancelled run performs no `lstat`/`read_dir`. An interrupted rule keeps its partial bytes;
  unstarted rules report zeros. (D18, D19)
- The 1000 skip cap counts attempts, regardless of whether the sink accepted the write. (D20)
- A non-directory root counts as a single entry (still age-filtered and deduped). Dedupe only tracks `nlink > 1`
  inodes and only after the age filter. (D21)
- **Permission on the root itself (new rule):** if `lstat` of a *root* fails with EACCES/EPERM (e.g. TCC-protected
  `ios-backups`), the rule is `partial` with one `skipped{reason:"permission_denied"}` and bytes 0 — **not** `refused`.
  `refused` is reserved for guard verdicts (deny list, symlinked root, `..`, absolute) and for other `Io` errors on the root.

### Ratified after 002b red phase (2026-11-07; full A1–A11 in `002b-test-matrix.md` §6)
- **Test seams** (`CLEANER_TMUTIL`, `CLEANER_TEST_VOLUME`) are honored only when the INV-15 test-mode guard is on;
  if set while the guard is off the binary **refuses** (exit 3) rather than silently ignoring (fail-closed; keeps
  hermetic tests from ever running real tmutil).
- `--rule` + `--tier` = intersection; empty intersection or unknown id/tier = exit 2; rules always scan in table order.
- **A scan never prunes old audit logs** (retention is a deletion; it needs its own spec and opt-in). Old logs accumulate until then.
- Permission hint: stdout in human mode, stderr in `--json`; the audit-unavailable warning always goes to stderr.
- Human layout is pinned by tokens only; byte units are base-10 (`B kB MB GB TB PB EB`, one decimal).
- `cleaner-cli` is a lib + thin bin. One `unsafe` block is permitted in `cleaner-macos` (`mod volume`, objc2 extern statics)
  with a `// SAFETY:` comment per ADR 0002; no other `unsafe` anywhere.

## Inputs & paths touched
Reads metadata only (`lstat`, directory listing) under the rule roots above; one `tmutil` read-only invocation;
Foundation volume-resource query. Writes: audit log only.

## Failure modes & handling
Permission denied (AC-002-7), vanished (8), absent (10), cross-device (6), symlink loop (5), sink unavailable (17),
volume query failure (2), tmutil failure (21), Ctrl-C (18), overflow (4), non-UTF-8 names (16), very deep trees
(iterative walk, no recursion-depth stack overflow: test with depth ≥ 10 000 in the in-memory `Fs`).

## CLI surface
```
cleaner scan [--rule ID]... [--tier TIER] [--top N] [--json]
exit: 0 ok · 2 usage · 3 test-mode refusal · 4 partial (skips, unknown volume/snapshots, log unavailable) · 130 interrupted
```
Example (human):
```
Volume /System/Volumes/Data      total 494.4 GB   available 365.8 GB
Purgeable (managed by macOS)      4.2 GB          [not added to the totals below]
Local snapshots: 0
Reclaimable by this tool (read-only scan; nothing selected)
  Safe          6.1 GB   user-caches 4.0 · cargo-cache 1.2 · ...
  Caution       9.8 GB   coresimulator 8.1 · ...
  Report-only   0 B      ios-backups (permission denied: grant Full Disk Access to Terminal)
Audit log: ~/Library/Logs/mac-cleaner/audit-2026-11-06.jsonl  (run 01J...)
```

## Open questions
- Should a run with an unavailable audit log fail instead of warning? (Default chosen: warn + exit 4, since scan is read-only.)
