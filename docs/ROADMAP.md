# Roadmap

Legend: ⬜ not started · 🟦 in progress · ✅ done (all DoD items verified)

## Phase 1 – Identify purgeable and reclaimable space (read-only)
| Slice | Spec | Owner chain | Status |
|-------|------|-------------|--------|
| Repo hygiene, CI, toolchain pins, test-doc checker | (devops deliverables) | devops | ✅ locally verified · ⬜ CI never run on GitHub (repo not pushed) |
| Workspace skeleton, SafetyGuard, audit log, test-mode guard | 001 | tester → developer | ✅ (3 rounds; mutation-tested, no safety survivors) |
| Scan core: size accounting, rules, snapshots, report model | 002a | tester → developer | ✅ |
| Adapters + `cleaner scan` CLI (volume/purgeable, tmutil, read_dir, SIGINT, JSON/human) | 002b | tester → developer | ✅ 121 tests green; runner mutants killed (2 equivalents documented) |
| First real-machine scan, reviewed with the user | – | user decision | ⬜ needs user OK (writes `~/Library/Logs/mac-cleaner/`) |

### Phase-1 known limits / deferred (tracked, not forgotten)
- INV-06 `/usr/local` carve-out deferred: phase 1 denies all of `/usr`.
- Non-UTF-8 component case-folding is lossy (over-blocks); Unicode full case-folding (`ß`) untested.
- Scan never prunes audit logs (retention is a deletion; needs its own spec + opt-in).
- `cleaner scan` on TCC-protected roots, and SIGINT mid-walk in a real terminal, are untested on a real machine.
- Coverage floor in CI is 0 (raise to ~85% now that real code exists); license is a placeholder (`MIT OR Apache-2.0`), no LICENSE file.
- Devops leftovers: release/nightly workflows, `scripts/vm-test.sh`, runbooks, `docs/macos-notes.md`, dependency-update config.
- Minimum macOS is 15 (CI-testable); revisit if a VM matrix is added.

## Phase 2 – Safe cleanup (Trash only)  🟦  spec 003 drafted, awaiting user sign-off
| Slice | Spec | Owner chain | Status |
|-------|------|-------------|--------|
| Plan + Trash executor + write-ahead audit + `undo` for 6 Safe rules | 003 (+ ADR 0003) | tester → developer | 🟦 Draft: needs sign-off on rule set, 24 h recency guard, granularity, confirmation, manifest path |
| Permanent delete (`--permanent`, typed phrase) + empty Trash | 004 | – | ⬜ not written |

## Phase 3 – Caution rules + interactive selection  ⬜
## Phase 4 – Release  ⬜

## Open product questions (answer before the phase that needs them)
- Phase 2: confirm Trash-by-default and the permanent-delete confirmation phrase (INV-04).
- Phase 3: sign-off needed per Caution rule before any deletion (e.g. `old-downloads` age threshold).
- Audit log unavailable: currently scan warns and exits 4 (read-only); mutating phases will refuse (INV-13).
