# Using mac-cleaner

> **Status: phase 1, read-only.** Today the tool can *find and report* purgeable and reclaimable space.
> It cannot delete, move, or modify anything yet. Cleanup (move to Trash, undo) is specified in
> [spec 003](specs/003-plan-trash-executor-and-undo.md) but **not implemented**.
> Implemented specs: 001 (safety guard, audit log, test-mode guard), 002 (`cleaner scan`).
> _This file is updated with every user-visible change (see the orchestrator's Definition of Done)._

Platform: Apple Silicon Macs (`aarch64-apple-darwin`), macOS 15 or newer (older versions are untested).

## Build and run

There is no installer yet. Build from source (the toolchain is installed by `scripts/bootstrap.sh`):

```bash
. "$HOME/.cargo/env"          # once per shell, if cargo is not on your PATH
cargo build --release -p cleaner-cli
./target/release/cleaner --version
```

Set up the dev toolchain from scratch (checks first, installs only what is missing; add `--check` to only report):

```bash
scripts/bootstrap.sh              # interactive
scripts/bootstrap.sh --yes        # unattended: required + recommended tools
```

## Commands

```
cleaner --version        name, version, git commit, target
cleaner --help
cleaner scan [--rule ID]... [--tier TIER] [--top N] [--json]
```

### `cleaner scan`

Read-only. It looks at file *metadata* (names, sizes, dates), never file contents, and writes only an audit
log. Nothing in its output is "selected" or "recommended"; scanning is not choosing.

| Option | Meaning |
|--------|---------|
| `--rule ID` | Scan only this rule (repeatable). Unknown id → exit 2 with the list of valid ids. |
| `--tier safe\|caution\|report-only` | Scan only rules of that tier. With `--rule`, the **intersection** is scanned (empty intersection → exit 2). |
| `--top N` | List the N largest children per rule (default 5; `0` lists none). Children with 0 bytes are never listed. |
| `--json` | Print **only** JSON (schema `scan/1`) on stdout. Warnings and the permission hint go to stderr. |

With no selectors, every rule is scanned.

#### Example

```text
$ ./target/release/cleaner scan
Volume /   total 494.4 GB   available 361.4 GB
Purgeable (managed by macOS)   4.3 GB   [not added to the totals below]
Local snapshots: 0
Reclaimable by this tool (read-only scan; nothing selected)
  Safe              5.2 GB   user-caches 3.2 GB (permission denied) · homebrew-cache 1.2 GB · ...
  Caution          77.8 kB   old-downloads 77.8 kB
  Report-only          0 B
  user-caches: partial (permission_denied x10)
Some entries could not be read: grant Full Disk Access to your terminal app ... and scan again.
Audit log: ~/Library/Logs/mac-cleaner/audit-2026-11-06.jsonl  (run 01M6S1T8RM7856XVVTY7Q4PYDY)
```

#### How to read it

- **Purgeable** is space macOS itself can reclaim when it needs to (iCloud-evicted files, local snapshots, some
  caches). It is computed by macOS as *available-for-important-usage − available*. This tool **only reports it**; it
  cannot and will not free it, and it is **never added** to the reclaimable totals (the two overlap).
  If the query fails it prints `unknown`, never `0`.
- **Local snapshots** are Time Machine local snapshots listed by `tmutil listlocalsnapshots /` (no root needed).
  macOS does not report their size, so only count and dates are shown.
- **Reclaimable** is what this tool can name in its built-in categories ("rules"), measured in **allocated** disk
  bytes (hard links counted once, sparse files by real blocks, symlinks never followed, other volumes not entered).
  APFS clones may be over-counted.
- Totals are grouped by **tier**: `Safe` (regenerable caches/logs), `Caution` (could be user-visible loss),
  `Report-only` (listed, never deletable by this tool).
- Lines like `user-caches: partial (permission_denied x10)` name every rule that was **refused, partial or
  interrupted**, even at 0 bytes, so you can tell what was not fully measured. A permission-denied folder makes the
  number a *lower bound*, not zero.
- The last line is the audit log path and the run id.

#### Built-in rules

| Rule | Tier | What it measures |
|------|------|------------------|
| `user-caches` | Safe | `~/Library/Caches` (minus subtrees owned by a more specific rule) |
| `homebrew-cache` | Safe | `~/Library/Caches/Homebrew` |
| `user-logs` | Safe | `~/Library/Logs` (excluding this tool's own log folders) |
| `trash` | Safe | `~/.Trash` (needs Full Disk Access to read) |
| `xcode-derived-data` | Safe | `~/Library/Developer/Xcode/DerivedData` |
| `cargo-cache` | Safe | `~/.cargo/registry/{cache,src}`, `~/.cargo/git` |
| `npm-cache` | Safe | `~/.npm/_cacache` |
| `xcode-archives` | Caution | `~/Library/Developer/Xcode/Archives` |
| `ios-device-support` | Caution | `~/Library/Developer/Xcode/iOS DeviceSupport` |
| `coresimulator` | Caution | `~/Library/Developer/CoreSimulator/Devices` |
| `old-downloads` | Caution | regular files in `~/Downloads` last modified ≥ 90 days ago |
| `ios-backups` | Report-only | `~/Library/Application Support/MobileSync/Backup` (usually needs Full Disk Access) |

A rule whose folder does not exist is reported `absent` with 0 bytes; that is normal, not an error.

#### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed with nothing unreadable or unknown |
| 1 | Runtime error (e.g. `HOME` unset or not absolute) |
| 2 | Usage error (unknown rule/tier, bad flags); nothing scanned, no log written |
| 3 | Safety refusal (test-mode guard or a test-only variable set; see below) |
| 4 | **Partial**: something was unreadable (permission denied), the purgeable value or snapshot list was unknown, a rule was refused, or the audit log could not be written. Results are still printed. |
| 130 | Interrupted with Ctrl-C; partial results are shown and flagged `incomplete` |

#### JSON output (`--json`, schema `scan/1`)

Top-level keys, in order: `schema`, `run_id`, `home`, `volume`, `snapshots`, `snapshots_unparsed`,
`snapshots_error`, `rules`, `totals`, `notes`, `incomplete`, `interrupted`, `audit_unavailable`.

- `volume`: `mount_point`, `total`, `available`, `available_important`, `purgeable` (**`null` when unknown**),
  `purgeable_clamped`, `volume_error`.
- `rules[]`: `id`, `tier`, `status` (`ok | partial | absent | refused | interrupted`), `bytes` (allocated),
  `logical_bytes`, `items`, `skipped`, `skipped_by_reason`, `vanished`, `deduped_links`, `top[]` (`path`, `bytes`).
  Paths that are not valid UTF-8 also carry a `path_b64` field (lossless).
- `totals`: bytes per tier (`safe`, `caution`, `report-only`).
- `notes`: stable codes, not prose: `purgeable_is_os_managed`, `purgeable_and_reclaimable_not_additive`,
  `trash_move_frees_nothing_until_emptied`, `clone_overcount_possible`, `snapshot_sizes_unavailable`.

Changing this shape requires a new schema version (`scan/2`).

## The audit log

Every run writes `~/Library/Logs/mac-cleaner/audit-YYYY-MM-DD.jsonl` (date in **UTC**), one JSON object per line,
append-only, owner-only permissions (directory `0700`, file `0600`). A scan writes `run_start`, one `scan_result` per
rule, a `skipped` record per skipped path (first 1000 per run, then counted), and `run_end` (exit code, totals).
`seq` is gap-free per run. A scan **never deletes old logs**; they accumulate until a retention feature exists.
If the log cannot be written the scan still runs, prints a warning on stderr, and exits 4.

## Permissions (Full Disk Access)

macOS protects some folders (Safari caches, the Trash, iOS backups, …). Those show as `permission_denied` and the
scan exits 4. To measure them, grant **Full Disk Access to the terminal app you run the tool from** (not to the
binary): System Settings → Privacy & Security → Full Disk Access → add your terminal, then restart it. The tool never
tries to bypass this, never prompts for it, and never uses `sudo`.

## Safety guarantees that already hold

- Read-only: a scan never creates, changes, moves, or deletes anything except its own audit log.
- A hard-coded deny list (system folders, `~/Documents`, `~/Desktop`, `~/Pictures`, Keychains, `~/.ssh`, …) can never be
  a scan root; it survives macOS case-insensitivity, Unicode name variants, and the `/var`·`/etc`·`/tmp` aliases.
- Symlinks are never followed; other volumes are not entered; no network access; file contents are never read.

## Environment variables

- `NO_COLOR` disables color. `HOME` must be set and absolute.
- **`CLEANER_TEST_MODE`**: for tests only. If it is set to anything other than empty or `0`, the tool refuses to run
  (exit 3) unless `HOME` is inside the system temp directory. If you see
  *"refusing to run in test mode: HOME (...) is not strictly inside the system temp dir"*, run `unset CLEANER_TEST_MODE`.
- `CLEANER_TMUTIL`, `CLEANER_TEST_VOLUME`: test-only seams. Honored only in test mode; set without test mode they are
  **refused** (exit 3, e.g. *"CLEANER_TMUTIL is a test seam and CLEANER_TEST_MODE is not enabled"*). Do not set them.

## Developer commands

```bash
just check test lint        # `test` runs via scripts/with-scratch-home.sh: tests never see your real HOME
just safety                 # safety regression suite only
just test-docs              # enforce the test documentation policy
just cov mutants deny audit # coverage, mutation testing (slow), supply-chain checks
```

Never run tests or experiments against your real home; use `scripts/with-scratch-home.sh <command>`.

## Not yet available

Anything that changes your files: `clean`, `plan`, `undo`, permanent deletion, emptying the Trash, scheduling,
interactive selection, Homebrew/`brew cleanup`-style vendor cleanup, a packaged installer. See
[ROADMAP.md](ROADMAP.md) for the phases.
