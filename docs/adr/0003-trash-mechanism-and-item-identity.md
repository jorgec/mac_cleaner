# ADR 0003 – How items are moved to the Trash, and how we prove the item is the one we planned

Status: Proposed (needs user sign-off with spec 003) · Date: 2026-11-07

## Context
Phase 2 is the first phase that mutates user data. INV-04 requires reversible-by-default deletion
(Trash) and INV-07 requires re-validation immediately before each mutation. Two decisions are costly
to reverse: *how* we trash, and *what we compare* to make sure the thing we trash is the thing we planned.

## Options for trashing
A. **`NSFileManager trashItemAtURL:resultingItemURL:error:`** via `objc2-foundation` (Rust FFI in `cleaner-macos`).
   Returns the resulting Trash URL (needed for the undo manifest); handles per-volume Trashes and name collisions.
   Unverified: whether it records Finder "Put Back" metadata on every macOS version.
B. Hand-rolled `rename` into `~/.Trash`. Simple, but wrong across volumes, name-collision logic is ours, no Put Back.
C. Drive Finder via `osascript`. Slow, needs Automation (TCC) permission, injectable strings.
D. `rm`/`remove_dir_all`. Rejected: not reversible (violates INV-04).

## Decision
**A.** Behind the port `Trasher::trash(&SafePath) -> Result<Trashed { trash_path }, TrashError>`; the *only*
mutating port, implemented only in `cleaner-macos`, called only by `executor`.
- The undo manifest (our own record: original path → trash path, written write-ahead and fsynced) is the
  **source of truth for `cleaner undo`**. We do **not** rely on Finder's Put Back, so the open question above
  does not affect correctness; a real-trash integration check is recorded as an `#[ignore]`d VM test.
- If `trashItem` fails for an item, the item is reported `failed`; **there is no fallback to deletion** (INV-04).
- A `DirTrasher` (moves into a given directory) exists for hermetic CLI tests, selectable only via the
  test-mode-guarded seam `CLEANER_TRASH_DIR` (refused with exit 3 outside test mode, like the other seams).
  Default tests never touch the real Trash (INV-15).

## Identity check ("is it still the thing we planned?")
The plan records, per item, `(dev, ino, file_type, mtime_ns, allocated_bytes)` from `lstat` at plan time
(for directories, plus the newest descendant mtime). Immediately before trashing, the executor re-runs
`SafetyGuard::admit` and re-`lstat`s the item: any change in `(dev, ino, file_type)` ⇒ `skipped{changed_since_plan}`;
a changed newest-descendant mtime (activity after planning) ⇒ `skipped{changed_since_plan}`. We never trash
something we can't prove is what the user was shown. (A TOCTOU window of microseconds between the check and
`trashItem` remains; it is bounded by the guard's no-symlink walk and the fact that the action is a reversible
move. Documented, not eliminated.)

## Consequences
+ Reversible, auditable, and the undo path does not depend on undocumented Finder behavior.
+ One audited mutation door; clippy bans stay intact (`remove_*`/`rename` still banned outside executor/adapters).
– `trashItem` moves are cheap but **free no space until the Trash is emptied**; reports must say so (INV-12).
  Emptying the Trash and `--permanent` are deferred to spec 004 (typed-phrase confirmation).
– One more `unsafe`-adjacent FFI surface in `cleaner-macos` (kept safe if the objc2 bindings allow).
