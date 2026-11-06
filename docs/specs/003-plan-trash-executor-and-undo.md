# 003 – Plan, move-to-Trash executor, and undo (Safe tier only)
Status: **Draft – needs user sign-off** (introduces deletion targets) · Owner: orchestrator · Risk tier: Safe (6 rules)
Depends on: 001, 002, ADR 0003

## Problem / user value
Phase 1 shows where reclaimable space is. Phase 2 lets the user act on it **carefully**: choose rules,
see the exact plan, confirm, and have the chosen items **moved to the Trash** (reversible), with every step
audited and a one-command `undo`. Nothing is selected by default; nothing is ever permanently deleted here.

## Non-goals (deferred to spec 004 or later)
Permanent deletion / `--permanent`; emptying the Trash (the `trash` rule is **not** enabled in phase 2);
`Caution` and `Report-only` rules; interactive per-item TUI selection; vendor cleanup commands (`brew cleanup`,
`simctl`); `tmutil` snapshot thinning; scheduling; audit-log retention (pruning).

## Enabled rules (the only deletion targets introduced; all tier `Safe`)
| rule | what is planned |
|------|-----------------|
| `user-caches` | each immediate child of `~/Library/Caches` not owned by a more specific rule |
| `homebrew-cache` | each immediate child of `~/Library/Caches/Homebrew` |
| `user-logs` | each immediate child of `~/Library/Logs` except `mac-cleaner`, `mac-cleaner-dev` |
| `xcode-derived-data` | each immediate child of `~/Library/Developer/Xcode/DerivedData` |
| `cargo-cache` | each immediate child of `~/.cargo/registry/cache`, `~/.cargo/registry/src`, `~/.cargo/git` |
| `npm-cache` | each immediate child of `~/.npm/_cacache` |

An **item** = one immediate child of a rule root (file, directory, or symlink — a symlink is trashed as a link).
**A rule root itself is never an item** (AC-001-5). Selecting a rule outside this table (`trash`, any Caution or
Report-only rule) is refused (AC-003-3).

## Concepts
- **Plan**: immutable, serializable list of `PlannedAction { rule_id, tier, item_path (SafePath), kind, allocated_bytes,
  identity{dev, ino, file_type, mtime_ns, newest_mtime_ns} }` plus `plan_id` (hash of the canonical plan), `run_id`,
  `created`. Same fs state + same selectors ⇒ **byte-identical plan** (stable ordering: rule order, then path bytes).
- **Recency guard** (protects running apps): an item whose `newest_mtime` (newest descendant) is newer than
  `now − 24 h` is planned as `excluded{recently_modified}` and **not** executed unless `--include-recent`.
- **Trash move frees no space** until the Trash is emptied; output reports `moved_bytes` and `reclaimed_bytes: 0` (INV-12).

## Behavior

### Selection and safety posture
- **AC-003-1 [INV-01,INV-02] Dry-run default; nothing selected by default.** `cleaner clean --rule R…` builds and prints
  the plan and exits 0 **without mutating anything**. `--apply` is the only way to execute. `cleaner clean` with no `--rule`
  → exit 2 listing the enabled rule ids; `--tier` alone is not a selector for `clean`. No output marks anything "recommended".
- **AC-003-2 [INV-14] Non-interactive.** Without a TTY, `--apply` requires `--yes` **and** at least one `--rule`;
  otherwise exit 2, nothing mutated. `--yes` never bypasses the recency guard (`--include-recent` is a separate flag).
- **AC-003-3 [INV-05] Tier gate.** Unknown rule id or id of a disabled rule (`trash`, Caution, Report-only) → exit 2 naming the id and
  why ("not available in this version"); nothing planned, no log created (usage error before any I/O).
- **AC-003-4 [INV-15] Test-mode guard first**, and the `CLEANER_TRASH_DIR` seam is honored only when the guard is on
  (refused with exit 3 otherwise, per AC-002 seam policy).
- **AC-003-5 `--exclude <path-relative-to-root>`** (repeatable) removes items from the plan before it is shown; an exclusion that
  matches nothing is a warning, not an error; exclusion is by exact component path, never glob-through-symlink.

### Planning
- **AC-003-6 [INV-12] Plan = scan accounting.** Plan bytes per item use allocated bytes with the run-wide hardlink dedupe and
  nested-rule claim logic of spec 002; sum of planned bytes ≤ the rule's `scan` bytes; items are children only.
- **AC-003-7 [INV-06,INV-07,INV-08] Every item passes `SafetyGuard::admit` under its rule root.** An item that is denied, a symlink
  escape, or on another device is **not planned** and is reported `excluded{<reason>}` (visible in the plan output), never silently dropped.
- **AC-003-8 Recency guard** (see Concepts): boundary exactly 24 h old is **eligible** (`<=`); a future mtime counts as recent.
- **AC-003-9 [INV-09] Protected items** (immutable `uchg/schg` flags, `EPERM`/`EACCES` on `lstat`, mounts) are `excluded{protected|permission_denied}`.
- **AC-003-10 [INV-03] Plan display and log.** The full plan (every action and every exclusion) is written to the audit log
  (`plan` record, chunked) **before** confirmation; the terminal shows per-rule counts/bytes and the top 20 items by size (`--show-all` for all).

### Confirmation
- **AC-003-11 [INV-03,INV-04] Final confirmation names the totals.** Interactive: "Move N items (X GB) from R rules to the Trash? [y/N]" — default
  **No**; anything but `y`/`yes` aborts with exit 0 and a `confirm{answer:"no"}` record. `--yes` records `confirm{via:"flag"}`.
  Executing requires a `ConfirmedPlan` value that only the confirmation step can construct.

### Execution (the only mutating code: `core::executor`, `Trasher` port)
- **AC-003-12 [INV-11] Write-ahead audit.** For each action, in plan order: `intent` (fsynced) → identity re-check → `trash` → `outcome`
  (+ manifest entry fsynced). `outcome` cannot be written without its `intent` (type-level token). Per-item failure is recorded and execution
  continues; **if an audit write fails, execution stops immediately** (INV-13), report `aborted_audit_unavailable`, exit 4.
- **AC-003-13 [INV-07] Re-admission + identity re-check immediately before each trash.** Re-run `SafetyGuard::admit`; re-`lstat`;
  `(dev, ino, file_type)` changed or newest descendant mtime changed ⇒ `skipped{changed_since_plan}` (nothing moved). Swapping a plan item for a
  symlink to a denied path between plan and execution moves **nothing outside the root** and logs `skipped{symlink_escape}`.
- **AC-003-14 [INV-04] No deletion fallback.** If `Trasher::trash` fails (any error) the item is `failed{<kind>}`; no `remove_*`, no retry
  with other means. The executor is the only module allowed `Trasher`; clippy bans stay.
- **AC-003-15 Vanished.** Item gone before its turn → `skipped{vanished}` (not an error).
- **AC-003-16 Cancellation.** SIGINT: finish the current item, stop, write `run_end{interrupted:true}`, exit 130; remaining actions logged as `skipped{interrupted}`.
- **AC-003-17 [INV-12] Honest result.** Final report: counts `moved/skipped/failed`, `moved_bytes`, `reclaimed_bytes: 0`, note code
  `trash_move_frees_nothing_until_emptied`, the audit log path, the run id and the undo hint `cleaner undo <run_id>`.
- **AC-003-18 Exit codes.** 0 all selected items moved (or dry-run / user declined / nothing to do); 4 if any item skipped-for-cause
  (`changed_since_plan`, `protected`, `permission_denied`) or failed; 130 interrupted; 2 usage; 3 safety/test-mode refusal.
  Recency exclusions alone do not make exit 4.

### Undo
- **AC-003-19 [INV-01] `cleaner undo <run_id>` is dry-run by default** (lists what would be restored); `--apply` restores.
  Source of truth: `~/Library/Application Support/mac-cleaner/runs/<run_id>/manifest.jsonl` (original path → trash path, identity), appended and fsynced
  per item during execution (written *write-ahead of the outcome* so a crash still leaves a usable manifest).
- **AC-003-20 Never overwrite.** If the original path now exists → `skipped{destination_exists}`; if the trash item is gone (user emptied the Trash)
  → `skipped{gone}`; restores re-admit the original path through the guard and only recreate missing parents inside the original rule root.
  Each restore is audited (`intent`/`outcome`, run id of the undo run, `undo_of: <run_id>`). Unknown/invalid run id → exit 2.
- **AC-003-21 Undo exit codes** mirror AC-003-18 (4 when anything could not be restored).

## Inputs & paths touched
Reads: metadata under the six rule roots (spec 002 walker). **Mutates:** moves items (children of rule roots only) into the Trash.
Writes: audit log (`~/Library/Logs/mac-cleaner/`), manifest (`~/Library/Application Support/mac-cleaner/runs/<run_id>/`, dir `0700`, files `0600`).
Hard deny list, no-symlink-following, device boundary, and everything in `safety-invariants.md` apply unchanged.

## Failure modes & handling
Trash unavailable/full or `trashItem` error → item `failed`, no fallback; permission denied → `skipped`; item changed/vanished/swapped → skipped;
audit or manifest not writable → refuse to start (before any move) with exit 4 (INV-13); Ctrl-C → AC-003-16; app running (recent writes) → recency guard;
Trash on another volume → handled by `trashItem`; name collision in Trash → handled by `trashItem`, resulting path recorded.

## Logging (additions to the contract; schema stays 1, new kinds)
`plan` (chunked: actions + exclusions + totals + `plan_id`), `confirm` (`via: prompt|flag`, `answer`), `intent` (action idx, path, rule, bytes, identity),
`outcome` (`moved|skipped|failed`, `reason`, `trash_path`), plus existing `run_start`/`run_end` (with `moved_items`, `moved_bytes`). `skipped` unchanged.

## CLI surface
```
cleaner clean --rule ID [--rule ID]... [--exclude REL]... [--include-recent] [--show-all] [--apply] [--yes] [--json]
cleaner undo RUN_ID [--apply] [--json]
exit: 0 ok/dry-run/declined · 2 usage · 3 safety/test-mode refusal · 4 partial/failed · 130 interrupted
```
Example (dry-run):
```
DRY RUN: nothing will be changed. Use --apply to move these items to the Trash.
Plan 7QK… (run 01M6…)   user-caches: 41 items 2.9 GB   user-logs: 18 items 55.2 MB
  top items: com.spotify.client 1.1 GB · … (+ excluded: com.apple.Safari permission_denied, 3 recently_modified)
Moving to the Trash frees no space until you empty the Trash.
```

## Sign-off questions (answer before implementation starts)
1. **Rule set** above (6 Safe rules; `trash` rule/empty-Trash and permanent delete deferred to 004). OK?
2. **Recency guard** default 24 h (skip items modified in the last day; `--include-recent` overrides). OK, or different window?
3. **Granularity:** rule-level selection plus `--exclude` per item (no interactive per-item TUI until phase 3). OK?
4. **Confirmation:** `[y/N]` with totals (no typed phrase because the action is reversible). OK?
5. **Undo manifest location:** `~/Library/Application Support/mac-cleaner/runs/`. OK?

## Open questions
- Whether `trashItem` records Finder "Put Back" on all macOS versions (ADR 0003: not relied upon).
