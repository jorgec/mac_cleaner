# ADR 0002 – How to obtain APFS purgeable space

Status: Accepted · Date: 2026-11-06

## Context
Phase 1's top priority is *identifying purgeable space*. macOS defines it through Foundation
volume resource keys, not through POSIX: purgeable ≈
`volumeAvailableCapacityForImportantUsage − volumeAvailableCapacity`.

Facts checked on an M-series Mac (read-only, 2026-11-06, Data volume):
- `df`/`statfs`: reports only "available" (excludes purgeable); cannot see it.
- `diskutil info -plist`: exposes `APFSContainerFree`, `CapacityInUse`, but **no purgeable key**.
- `tmutil listlocalsnapshots /`: lists snapshot names/dates, **no sizes**, no root needed.
- Foundation `URLResourceValues` (via a throwaway Swift script): total 494,384,795,648;
  available 365,789,609,984; important 369,982,967,776 → purgeable ≈ 4.19 GB. ✔ obtainable.

## Options
A. **`objc2-foundation` (Rust bindings) calling `NSURL` resource values** from `cleaner-macos`.
B. Shell out to `swift`/`osascript`. Needs a toolchain on the user's machine, slow, brittle.
C. `diskutil`/`df` parsing. Cannot see purgeable (above).
D. Private/undocumented APIs. Rejected: unstable, not notarization-friendly.

## Decision
Option A, behind the port `VolumeCapacity::query(path) -> Result<VolumeCaps, VolumeError>` where
`VolumeCaps { mount_point, total, available, available_important, available_opportunistic }`.
- `purgeable = max(0, available_important − available)`; clamp flagged (`purgeable_clamped`).
- Failure to query yields `purgeable: null` + `volume_error`, **never 0** (INV-13: unknown ≠ none).
- FFI (if any `unsafe` is required) lives only in `cleaner-macos`, each block `// SAFETY:`.
- An opt-in macOS integration test (`#[ignore = "requires-swift-oracle"]`) compares the adapter
  against the Swift oracle script within a 1 MiB tolerance (values drift while running).
- Crate versions are verified on crates.io at implementation time (objc2-foundation was 0.3.x).

## Consequences
+ Matches what Finder/Disk Utility call purgeable.
+ Clean seam: all logic is tested with a fake `VolumeCapacity`.
– Depends on Apple API semantics; the oracle test is the early-warning system on new macOS releases.
– Purgeable is not itemizable by this tool; we report the OS number plus what we *can* name
  (local snapshots, count only) and state the remainder is OS-managed.
