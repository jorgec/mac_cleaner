# 001 – Workspace skeleton, SafetyGuard, audit log, test-mode guard
Status: Approved · Owner: orchestrator · Risk tier: n/a (no deletion targets; read-only foundation)

## Problem / user value
Everything later (scan, then deletion) rests on three trusted components: a **path safety
guard** that decides what may ever be touched, an **audit log** that records what the tool did,
and a **test-mode guard** that makes it impossible for tests to hit the real machine.
Build them first, small, and prove them hard.

## Non-goals
Executor, Trash, config-file loading, any mutation of user files. (Audit *intent/outcome*
records are deferred to phase 2 when mutation exists; the log format reserves them.)

## Terms
`HomeDir` = injected absolute home path (never read from the environment inside `core`).
`SafePath` = a path that passed `SafetyGuard::admit`; the only type later phases accept.

## Behavior

### SafetyGuard (`cleaner-core::safety`)
Signature (contract, names may vary): `admit(&self, fs: &dyn Fs, root: &Path, candidate: &Path) -> Result<SafePath, Denied>`.
`Denied` is an enum with a stable `kind` per cause (used in logs and tests): `NotAbsolute`,
`Traversal`, `DenyListed`, `AncestorOfDenied`, `OutsideRoot`, `SymlinkEscape`, `CrossDevice`, `Io`.

- **AC-001-1 [INV-06] Deny list is exact on path components.**
  Given `HomeDir=/Users/u`; When admitting `/Users/u/Documents`, `/Users/u/Documents/a/b`,
  `/System/Library/x`, `/Users/u/.ssh/id_rsa` (each as candidate under a root that would
  otherwise contain it); Then `Err(DenyListed)`. Boundary: `/Users/u/Documents-old/x`
  and `/Users/u/Documentsx` are **not** denied (component match, not string prefix).
  Must never: touch the filesystem for this verdict beyond path resolution.
- **AC-001-2 [INV-06] Ancestors of denied paths are denied.**
  `/`, `/Users`, `/Users/u` (home itself), `/Users/u/Library` as *candidate* → `Err(AncestorOfDenied)`
  (deleting an ancestor would delete a denied descendant). A sibling like `/Users/u/Library/Caches`
  is admitted if otherwise valid.
- **AC-001-3 [INV-06] Firmlink normalization.**
  `/System/Volumes/Data/Users/u/Documents/x` is treated identically to `/Users/u/Documents/x`
  (→ `DenyListed`). Property: `normalize` is idempotent and never turns an allowed path into a denied one
  or vice-versa except via this prefix rule.
- **AC-001-4 [INV-07] Syntax rejection.**
  Relative paths → `NotAbsolute`; any `..` component (even if it would resolve inside the root) → `Traversal`;
  empty path → `NotAbsolute`. Redundant `//` and `/./` are normalized, not rejected. Non-UTF-8 byte
  paths are handled (no panic) and judged by the same rules.
- **AC-001-5 [INV-07] Root containment is component-wise.**
  Root `/Users/u/Library/Caches`: candidate `/Users/u/Library/Caches/app/x` admitted;
  `/Users/u/Library/Caches-old/x` → `OutsideRoot`; the root itself is admitted as the *root*
  only through `admit_root`, not as a deletion candidate (`admit` of the root → `OutsideRoot`),
  so a rule can never delete its own root directory.
  **Amended:** `admit_root` on a root that does not exist returns `Ok` with `exists=false` (an absent
  root is not unsafe; nothing can be touched), after the lexical/deny/symlink checks that can be made;
  any other `Fs` error is `Io`. Spec 002 relies on this for `status:"absent"` (AC-002-10, AC-002-11).
- **AC-001-6 [INV-07] Symlinks are never followed.**
  Given a symlink `root/link → /Users/u/Documents`: admitting `root/link` yields a `SafePath`
  flagged `is_symlink=true` (the link itself may be removed as a link); admitting `root/link/secret`
  → `SymlinkEscape` (a parent component resolves outside the root). A symlinked *root*
  → `SymlinkEscape`. A symlink loop terminates with an error, not a hang. Dangling link: admitted as link.
- **AC-001-7 [INV-08] Device boundary.**
  Given `Fs::device_of` reports a different device for a candidate (or its parent) than the root →
  `Err(CrossDevice)`; same device admitted.
- **AC-001-8 [INV-06] User config can only add to the deny list.**
  `SafetyGuard::with_extra_denied(paths)` makes those paths denied **and** the built-in entries
  remain denied; there is no API to remove or override a built-in entry (compile-level: no such method).
- **AC-001-9 [INV-07] TOCTOU re-validation contract.**
  `admit` performs resolution via `Fs` on every call (no caching of verdicts): swapping a directory
  for a symlink between two `admit` calls on the same input changes the verdict to `SymlinkEscape`.
- **AC-001-10 [INV-13] Fail closed.** Any `Fs` error while resolving → `Err(Io)`; never `Ok`.

- **AC-001-17 [INV-06] Deny matching survives APFS name aliasing (added after developer review).**
  Default APFS volumes are case-insensitive and normalization-insensitive, so `/Users/u/documents`,
  `/users/u/Documents`, and an NFD spelling of a denied name are the *same* directory as the denied one.
  Deny-list and ancestor comparison therefore uses a **folded** key per component (Unicode case-fold + NFC);
  over-blocking is acceptable, under-blocking is not. Containment (`OutsideRoot`) stays exact/case-sensitive
  so a folded match never *admits* something. Boundaries: `Documents-old`, `Documentsx` remain admitted;
  `DOCUMENTS`, `documents`, NFD-composed variants, and `Library/KEYCHAINS` are `DenyListed`.
  (If NFC folding needs a new crate, justify it; `unicode-normalization` is the expected choice.)
- **AC-001-18 [INV-06] `/private` aliases.** `/var`, `/etc`, `/tmp` are symlinks to `/private/{var,etc,tmp}`.
  `normalize` rewrites a leading `/var`, `/etc`, `/tmp` component to `/private/...` (alongside the firmlink
  prefix rule) so `/var/db/x` is judged as `/private/var/db/x`. Idempotent; no other paths change.
  Composition roots (CLI) must pass canonicalized rule roots to `admit_root`; document this on `admit_root`.

### Audit log (`cleaner-core::audit`, file sink in `cleaner-macos`)
Format and location per `safety-invariants.md` ("Logging contract"). Records for phase 1:
`run_start`, `scan_result`, `skipped`, `run_end` (+ reserved variants for phase 2).
- **AC-001-11 [INV-11] JSONL contract.** Each record is one line of valid JSON with
  `schema:1`, `ts` (RFC 3339 UTC, from injected `Clock`), `run_id`, `seq` (starts at 1, strictly +1, no gaps),
  `kind`. Unknown-future fields are tolerated on read. A record never contains a raw newline
  (embedded newlines in paths are escaped by JSON).
- **AC-001-12 [INV-11,INV-13] Durability and permissions.** Directory created `0700`, file `0600`;
  opened append-only; each record is flushed before `record()` returns; existing logs are appended
  to, never truncated. If the directory/file cannot be opened, constructing the sink returns
  `Err(AuditError::Unavailable)` (callers decide policy; see spec 002).
- **AC-001-13 [INV-16] Path fidelity.** A path with non-UTF-8 bytes is recorded losslessly
  (`path` lossy string + `path_b64` base64 of the raw bytes, present only when lossy ≠ original).
- **AC-001-14 Rotation/retention.** One file per UTC day (`audit-YYYY-MM-DD.jsonl`) chosen via the
  injected clock; `prune(retain_days=90)` removes only `audit-*.jsonl` older than the cutoff, never the
  newest file, never other files in the directory. (Pruning logic is core; the actual removal goes
  through a dedicated `LogStore::remove` port method - the sole mutation allowed in phase 1.)

### Test-mode guard (composition root + `core::testmode`)
- **AC-001-15 [INV-15] Refuse real home in test mode.** With `CLEANER_TEST_MODE=1`, the CLI requires
  `HOME` to be a canonical path inside the system temp directory; otherwise exit code `3`
  with message naming the offending path and **no log file created, no scan started**.
  **Amended (fail-closed):** the guard is OFF only when the variable is unset, empty, or exactly `0`;
  any other value (`1`, `true`, `yes`, …) turns it ON. (A typo must not silently disable the protection.)
  `home == temp_dir` itself, relative homes, and `..` components are violations.
  The decision function is pure (`fn check(test_mode: bool, home: &Path, temp_dir: &Path) -> Result<(), TestModeViolation>`).

### Workspace
- **AC-001-16 Build gates.** `cargo build`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check` pass. `cleaner-core` has `#![forbid(unsafe_code)]`. `clippy.toml` bans
  `std::fs::{remove_file,remove_dir,remove_dir_all,rename,write,copy}` and `std::process::Command::new`
  outside the allowed modules (verified by a deliberately failing sample under `tests/lint/` that CI expects to fail).
  `cleaner --version` prints name, version, git SHA, and target triple.

## Inputs & paths touched
Reads: path metadata only via `Fs`. Writes: `$HOME/Library/Logs/mac-cleaner/` (audit) only.
Deny list (built-in, code): see INV-06; home-relative entries expand from the injected `HomeDir`.

## Failure modes & handling
Unreadable path → `Io`; log dir unwritable → `AuditError::Unavailable`; clock before epoch → still
formats (clamped) and never panics; extremely long path → rejected as `Io(ENAMETOOLONG)` not panic.

## Logging
Defined above (AC-001-11..14).

## CLI surface
`cleaner --version`, `cleaner --help`. (`scan` arrives in spec 002.) Exit codes per safety-invariants.md.

## Ratified decisions (orchestrator, 2026-11-06; detail in `001-test-matrix.md` §5)
Accepted as the tester resolved them: check order syntax → deny → containment → fs; lexical verdicts make
zero `Fs` calls; `admit` does not deny-check the root (`admit_root` does); **any** symlink among parent
components is `SymlinkEscape`; `Denied.path` is the argument as passed; `SafePath.path()` is the normalized
spelling; ts `YYYY-MM-DDTHH:MM:SSZ`, standard padded base64; a failed write consumes no `seq`; `prune` keeps a
file exactly `retain_days` old, only considers valid `audit-YYYY-MM-DD.jsonl` names, never removes the newest;
`FileAuditSink::open` creates dir (leaf 0700) and file (0600) eagerly; `LogStore::remove` rejects non-plain names;
test-mode guard runs before argument parsing (even `--version`); nonexistent candidate → `Io`.
Phase 1 denies all of `/usr` including `/usr/local` (the INV-06 `/usr/local` carve-out is deferred until a rule needs it).

## Open questions
None blocking. (Default decisions: ULID-style sortable `run_id` from an injected generator; base64 via a vetted crate.)
