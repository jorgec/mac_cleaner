# Testing Policy (shared by all four cleaner skills)

Binding alongside `safety-invariants.md`. Three rules, in priority order:

1. **Test intentionally** – a test proves a *design promise*, not that code ran.
2. **Test frugally** – every test must earn its place; no padding, no duplicates.
3. **Document verbosely** – every test explains itself well enough that a reader who has
   never seen the spec can tell what is promised, why, and what bug it would catch.

## 1. Intentional: test "as designed", not "does it work"

A happy-path test shows the code can succeed. It does not show the code does what it was
*designed* to do. A function's design is its **contract**; test the contract:

| Contract facet | Question the test answers | Example (`SafetyGuard::admit`) |
|---|---|---|
| Postcondition | What is true after success? | Returned `SafePath` is canonical and inside the rule root |
| Precondition / rejection | What inputs must be refused, and *how* (which error)? | Path under `~/Documents` → `Err(Denied{reason: DenyList})`, not a generic error |
| Boundary | Where does behavior flip? | Path exactly equal to root vs one component above vs one below; age exactly at `min_age` |
| Negative / forbidden effect | What must it **never** do? | Rejection performs zero filesystem writes; zero audit `intent` records |
| Invariant | What holds regardless of input? | `admit` never returns a path that is a symlink escape (property test) |
| Idempotence / ordering | Does repeating or reordering change results? | `admit(admit(p)) == admit(p)`; plan order is stable |
| Error fidelity | Do failures carry the right context and exit code? | Error names the offending path and maps to exit code 3 |
| Failure of dependencies | What if a port misbehaves? | `Fs::lstat` returns `EPERM` → skipped + logged, no panic |

**Derive tests from the contract (spec AC, invariant, rustdoc of the function), never by
reading the implementation and asserting what it happens to do.** If the contract is
unclear, that is a spec bug: send it back to the orchestrator before writing the test.

### Per-function test design worksheet (write this in the test module header comment)

```
Function:        <path::to::fn>
Contract:        <1-3 lines: pre, post, errors, forbidden effects> (AC-xxx-n, INV-nn)
Equivalence classes:   <list each distinct behavior region>
Boundaries:      <each edge between classes>
Must-never:      <forbidden effects to assert absent>
Selected tests:  <class/boundary/must-never → test name>   (nothing else gets a test)
Deliberately not tested: <and why: covered by X / std behavior / out of scope>
```

## 2. Frugal: every test earns its place

A test is justified only if it does at least one of these **uniquely**:
- covers an acceptance criterion or invariant no other test covers,
- covers a distinct equivalence class or boundary no other test covers,
- asserts a must-never effect no other test asserts,
- kills a mutant no other test kills (confirmed by `cargo mutants`),
- pins a past bug (regression), linked to the issue.

Therefore:
- **One test per equivalence class and per boundary**, not ten inputs from the same class.
  Many inputs for one class → one table-driven/parameterized test with a named case list.
- **Test at the lowest level that can see the behavior.** Do not re-prove a unit's logic in
  an integration test or the CLI test; the higher level tests only wiring and contract
  (exit code, output shape, that the pieces are connected).
- **Do not test**: derived impls (`Debug`, `Clone`, serde derives unless the *format* is a
  contract), getters, `clap`/`serde`/`std` behavior itself, private helpers directly
  (cover via the public contract), or constants.
- **Share fixtures, not assertions.** Builders in `cleaner-testkit` keep tests short; don't
  copy-paste scenarios with one value changed.
- **Fast by default.** Unit tests are milliseconds. No sleeps. Heavy tests (large trees,
  VM, fuzz, mutation) are in named slower tiers, not the default loop.
- **Prune continuously.** After green, run `cargo mutants` on the diff. A test whose
  removal changes neither coverage of an AC/class/must-never nor the killed-mutant set is
  deleted in the same PR. Less, sharper tests beat more, vaguer ones.
- Frugal never means thin on safety: the safety regression suite (INV-*) is exempt from
  pruning pressure, only from duplication.

## 3. Verbose documentation of every test

Every `#[test]` (and every property test, proptest `fn`, and parameterized case list) has a
rustdoc comment using exactly these headings, in this order. Missing or hollow sections
(restating the function name) fail review. Keep them truthful: if the test changes, update
the doc in the same commit.

```rust
/// # Design promise
/// What the design guarantees, in plain words, with IDs: AC-003-2, INV-07.
///
/// # Scenario (Given)
/// The exact starting state, including *why* this state is interesting
/// (which equivalence class or boundary it represents).
///
/// # Action (When)
/// The single operation under test.
///
/// # Expected (Then)
/// Every observable outcome asserted, and the reasoning that makes each correct
/// according to the design (not "because the code returns it").
///
/// # Must never
/// Forbidden effects asserted absent (no writes, no log intent, no panic). "n/a" if none.
///
/// # Would catch
/// The concrete bug or mutant this test exists to catch (e.g. "using `metadata`
/// instead of `symlink_metadata` would follow the link and delete the target").
///
/// # Why this test (not redundant)
/// The unique class/boundary/AC it covers and what neighboring test(s) cover the rest.
#[test]
fn ac_003_2_symlink_to_denied_dir_is_unlinked_not_traversed() {
    // Arrange: <comment each fixture step and why it exists>
    // Act:
    // Assert: every assert! carries a message stating the violated promise
}
```

Inline rules:
- Comment each Arrange step with its purpose; separate Arrange/Act/Assert visibly.
- Every assertion has a message: `assert!(!target.exists(), "INV-07: denied target was
  removed through a symlink")`. A failure must explain which promise broke without opening
  the test.
- Name tests `ac_<spec>_<n>_<behavior_in_words>` or `inv_<nn>_<behavior_in_words>`.
- Table-driven cases carry a `name`/`why` field per row; the doc lists what each row represents.
- Fixtures and helpers get doc comments too (what state they build and what they guarantee).
- Snapshot tests: doc says what contract the snapshot pins and who may approve changes.

## Review checklist (orchestrator gate and tester self-check)

- [ ] Each test traces to an AC/INV/regression issue in its `# Design promise`.
- [ ] Test derived from the contract, not from the implementation.
- [ ] Includes rejection/boundary/must-never coverage where the contract has them, not only success.
- [ ] No two tests cover the same class/boundary/AC without a stated reason.
- [ ] All seven doc headings present and specific; assertion messages present.
- [ ] Mutation run on the diff; surviving mutants in safety code addressed; redundant tests removed.
- [ ] Nothing tested that the policy lists under "Do not test".
