# mac-cleaner – Product Spec

Status: Approved (phase 1 scope) · Owner: orchestrator
Binding companions: `.claude/skills/cleaner-orchestrator/references/{safety-invariants,testing-policy}.md`

## Purpose
A Rust command-line tool, in the spirit of CleanMyMac, that finds and (in later phases)
removes reclaimable disk space on Apple Silicon Macs, with **full logging** and **careful
opt-ins**. Safety beats features; every deletion is explicit, reversible by default, and audited.

## Platform decisions (defaults; change via ADR)
- Target `aarch64-apple-darwin` only (M1–M4). Intel out of scope.
- Minimum macOS **15 (Sequoia)**: the oldest version CI can exercise on a GitHub arm64 runner
  (macOS 14 runner images were retired 2026-11-02 per devops; amended from 14). Older versions
  may work but are untested; revisit if a self-hosted/VM matrix is added.
- Files and logs stay local; no network calls (INV-16).

## Vocabulary (used precisely everywhere)
| Term | Meaning |
|------|---------|
| **Purgeable space** | Space macOS itself can reclaim on demand (iCloud-evicted files, local Time Machine snapshots, some caches). Computed by the OS as `available-for-important-usage − available`. **OS-managed: this tool identifies it but never frees it directly.** |
| **Reclaimable space** | Space this tool can free by acting on files/commands it knows about (caches, logs, DerivedData…). Itemized per **rule**. May partly overlap with purgeable; the two numbers are **never summed**. |
| **Rule** | A declarative description of one reclaimable category: id, tier, roots, excludes, optional min age, explanation. |
| **Tier** | `Safe`, `Caution`, `Report-only` (INV-05). |
| **Scan** | Read-only metadata walk. Scanning is not selecting: scan output never pre-selects anything (INV-02). |

## Phases
| Phase | Goal | Mutates disk? |
|-------|------|---------------|
| **1 (current)** | **Identify purgeable and reclaimable space.** `cleaner scan`: volume capacity, purgeable estimate, local snapshots, per-rule reclaimable sizes, JSON output, full audit log. Skeleton, safety guard, audit log, CI. | **No** |
| 2 | Plan + Trash executor + write-ahead audit + `undo` for Safe rules. | Yes (Trash only) |
| 3 | Caution rules with per-item review; interactive selection UX. | Yes |
| 4 | Release: signing, notarization, Homebrew tap, `doctor`. | – |

Phase-1 specs: `docs/specs/001-workspace-skeleton-and-guards.md`, `docs/specs/002-purgeable-space-scan.md`.
Decisions: `docs/adr/`. Status tracking: `docs/ROADMAP.md`.

## Non-goals (all phases unless user changes them)
App uninstaller/remnant hunting, duplicate finder, language-pack stripping (breaks code
signatures), malware scanning, memory "optimizers", scheduled unattended deletion.
