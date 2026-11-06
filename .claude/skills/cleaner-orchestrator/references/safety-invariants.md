# Safety Invariants (shared by all four cleaner skills)

This file is the single source of truth. Orchestrator, tester, developer, and devops
all cite it. If a change would violate an invariant, stop and raise it with the user;
do not "work around" it. Changing an invariant requires an ADR and explicit user approval.

A cleaner's failure mode is deleting something the user needed. Every design choice
trades speed and feature count for the guarantee that **nothing is removed unless the
user knowingly asked for exactly that**.

## Behavioral invariants (INV-*)

| ID | Invariant |
|----|-----------|
| INV-01 | **Dry-run is the default.** No command mutates the filesystem or system state unless `--apply` (or the interactive confirm step) is reached. |
| INV-02 | **Nothing is selected by default.** Every category and rule is opt-in. No "select all recommended" shortcut. Opt-in may come from an explicit CLI flag (`--category caches`), the config file, or interactive selection. |
| INV-03 | **Scan → Plan → Confirm → Execute.** Phases are separate. The Plan is an immutable, serializable value (list of `PlannedAction`) that is shown to the user, logged in full, then executed exactly as shown. Execute never re-expands a rule into new paths. |
| INV-04 | **Reversible by default.** Deletion = move to Trash (or the tool's own supported cleanup command, e.g. `brew cleanup`). Permanent deletion needs `--permanent` AND a typed confirmation phrase, AND is unavailable for risk tier `Caution`. |
| INV-05 | **Risk tiers.** Every rule declares `Safe` (regenerable cache/log), `Caution` (may be user-visible loss: old downloads, iOS simulators, Xcode archives), or `Report-only` (never deleted by this tool: iOS device backups, Photos libraries, Mail, Documents, Desktop, Keychains, anything in iCloud Drive). |
| INV-06 | **Hard deny list is code, not config.** `/System`, `/usr` (except `/usr/local` rule-targeted subpaths), `/bin`, `/sbin`, `/private/var/db`, `/Library/Apple`, `~/Documents`, `~/Desktop`, `~/Pictures`, `~/Library/Keychains`, `~/Library/Mobile Documents`, `~/Library/Messages`, `~/.ssh`, `~/.gnupg`, and `/`, `$HOME` themselves can never be a deletion target, an ancestor of one, or reached via symlink. User config can *add* to the deny list, never remove from it. |
| INV-07 | **No symlink following.** Use `symlink_metadata`/`lstat`/`O_NOFOLLOW` semantics. A symlink is removed as a link, never traversed. Resolve (`canonicalize`) and re-validate against the deny list and the rule's root **immediately before** each mutation (TOCTOU guard). |
| INV-08 | **Stay on the rule's root and device.** Traversal must not cross mount points (compare `st_dev`) unless the rule explicitly says so. |
| INV-09 | **Skip what is in use or protected.** SIP-protected paths, paths with `uchg`/`schg` flags, paths open by a running process for known-sensitive rules, and paths that fail with `EPERM`/TCC denial are skipped and logged, never retried with escalation. |
| INV-10 | **No silent privilege escalation.** The tool never invokes `sudo` itself. Rules that need root say so, are listed as unavailable when not root, and the user must re-run knowingly. |
| INV-11 | **Write-ahead audit log.** Before each mutation, an `intent` record is appended and flushed (`fsync` for destructive tiers). After, an `outcome` record is appended. A crash leaves evidence of what was attempted. |
| INV-12 | **Accurate sizes.** Report allocated size (`st_blocks * 512`), dedupe hardlinks by `(dev, ino)`, never count the same inode twice, never report reclaimed bytes that were not actually freed (Trash move frees nothing until emptied; say so). |
| INV-13 | **Fail closed.** On any ambiguity (unparseable path, unknown rule version, config error, log directory unwritable) abort the mutating phase with a non-zero exit code. Read-only scan may continue with a warning. Never fall back to a more permissive behavior. |
| INV-14 | **Non-interactive safety.** Without a TTY, `--apply` requires `--yes` AND explicit `--category`/`--rule` selectors. `--yes` never bypasses INV-05 `Caution` per-item review unless `--accept-caution` is also given. Unattended/scheduled runs are report-only unless the user wrote an explicit config allowing otherwise. |
| INV-15 | **Tests never touch the real machine.** Test code and CI operate only on temp dirs / fake `$HOME`. A runtime guard (`CLEANER_ALLOW_REAL_FS` must be unset in tests) makes the executor refuse to run against the real home under `cfg(test)` or when `CLEANER_TEST_MODE=1`. |
| INV-16 | **Privacy.** Logs stay local, contain paths and sizes only (no file contents), and the tool makes no network calls. |

## Logging contract

Two sinks, both under `~/Library/Logs/mac-cleaner/` (mode `0700` dir, `0600` files):

1. **Audit log** `audit-<YYYY-MM-DD>.jsonl`: one JSON object per line, append-only,
   schema versioned (`"schema": 1`). Records: `run_start`, `scan_result`, `plan`,
   `confirm` (who/what/how: flag, prompt answer), `intent`, `outcome`, `skipped`,
   `run_end`. Common fields: `ts` (RFC 3339 UTC), `run_id` (ULID/UUID), `seq`,
   `rule_id`, `path`, `bytes`, `tier`, `result`, `error`.
2. **Diagnostic log** `cleaner-<YYYY-MM-DD>.log`: `tracing` output for humans,
   level via `--verbose`/`-v` or `CLEANER_LOG`. Never the only record of a mutation.

Retention: rotate daily, keep 90 days by default, never auto-delete the most recent
run's audit log. The tool prints the audit log path at the end of every run.

A **trash manifest** (`runs/<run_id>/manifest.json`) records original path → trash
path for each moved item so `cleaner undo <run_id>` can restore.

## Exit codes

`0` success (including "nothing to do") · `1` runtime error · `2` usage error ·
`3` safety refusal (deny list / invariant tripped) · `4` partial success (some items
skipped or failed) · `130` interrupted by user.

## Target platform

`aarch64-apple-darwin` only (Apple Silicon M1–M4), macOS 13+ (verify the minimum
against what CI can actually test; record in `docs/SPEC.md`). Intel is out of scope
unless the user changes it. APFS assumed: account for clones, sparse files, snapshots,
and firmlinked volume layout (`/System/Volumes/Data`).
