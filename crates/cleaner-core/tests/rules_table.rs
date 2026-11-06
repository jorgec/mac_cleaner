//! The built-in rule table and the claim logic (spec 002 "Built-in rules", AC-002-11, AC-002-9,
//! AC-002-22; INV-05, INV-06, INV-12).
//!
//! # Worksheet - `rules::builtin`
//! ```text
//! Function:        rules::builtin() -> Vec<Rule>
//! Contract:        exactly the twelve rules of the spec table (ids, tiers, roots, age filter,
//!                  user-logs excludes) in spec order; over the whole table: ids unique and
//!                  kebab-case, non-empty `explain`, roots relative to HOME without `..`, every root
//!                  admitted by `SafetyGuard::admit_root` (so none is, contains, or is below a
//!                  deny-listed path), Report-only rules not deletable, no root shared by two rules.
//!                  (AC-002-11; INV-05, INV-06)
//! Equivalence classes: the whole table, checked as data (one pin test + one invariants test)
//! Boundaries:      kebab-case edges (`a--b`, `-a`, `A`); rule order (it decides hardlink ownership)
//! Must-never:      a new or changed rule without a spec amendment; a deny-listed root; a deletable
//!                  Report-only rule
//! Selected tests:  ac_002_11_table_matches_the_spec_pin, safety::ac_002_11_table_invariants_...
//! Deliberately not tested: wording of `explain` (only non-empty), `user-caches` excludes (the
//!                  spec leaves "excluded by claim logic" vs "explicit exclude" open; both give the
//!                  same claims, which `owner_of` tests pin).
//! ```
//!
//! # Worksheet - `rules::owner_of`
//! ```text
//! Function:        rules::owner_of(&[Rule], rel_path) -> Option<&Rule>
//! Contract:        among rules with a root that is a component-wise prefix of `rel` (equality
//!                  counts) and whose `excludes` do not cover `rel`, the longest root wins; ties go
//!                  to the earlier rule; nothing else claims anything. (AC-002-9, AC-002-22)
//! Equivalence classes: inside the only matching root | nested root (most specific) | root itself |
//!                  look-alike sibling (`Caches-old`) | excluded subtree | excluded-by-A but inside B's
//!                  root | ancestor of a root | unrelated | tie between rules
//! Boundaries:      `Caches` vs `Caches-old` (component-wise), `mac-cleaner` vs `mac-cleaner-extra`
//! Must-never:      claim by string prefix; let two rules claim the same path; claim an excluded path
//!                  for the excluding rule
//! Selected tests:  safety::ac_002_9_owner_of_follows_the_spec_table, safety::ac_002_9_owner_of_logic_..
//! Deliberately not tested: performance with many rules.
//! ```

mod common;

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use cleaner_core::rules::{Rule, Tier, builtin, owner_of};
use cleaner_core::safety::{HomeDir, SafetyGuard};
use cleaner_testkit::FakeFs;
use common::HOME;

/// The id owning `rel` in `rules`, as the tests compare it.
fn owner<'a>(rules: &'a [Rule], rel: &str) -> Option<&'a str> {
    owner_of(rules, Path::new(rel)).map(|r| r.id.as_str())
}

/// # Design promise
/// Spec 002 "Built-in rules": the table is data and *exactly* the approved one; "adding a rule
/// requires its own spec amendment" (so an added, removed, reordered or edited rule must fail here).
///
/// # Scenario (Given)
/// The spec table transcribed as `(id, tier, roots, min_age days)` plus the two `user-logs`
/// excludes.
///
/// # Action (When)
/// `builtin()`.
///
/// # Expected (Then)
/// The same 12 ids in the same order (order = hardlink ownership order); per rule the same tier,
/// the same roots in the same order, the same age filter (`old-downloads` 90 days, all others
/// `None`); `user-logs` excludes exactly `Library/Logs/mac-cleaner` and
/// `Library/Logs/mac-cleaner-dev`; every other rule except `user-caches` has no excludes.
///
/// # Must never
/// Differ from the spec table silently.
///
/// # Would catch
/// A silently added/removed rule, `Caution` changed to `Safe` for `xcode-archives`, a dropped
/// `cargo-cache` root, the log rule reporting the tool's own logs as reclaimable.
///
/// # Why this test (not redundant)
/// The only equality pin of the table to the spec; the invariants test checks generic validity.
#[test]
fn ac_002_11_table_matches_the_spec_pin() {
    // Arrange: the spec table.
    let spec: [(&str, Tier, &[&str], Option<u64>); 12] = [
        ("user-caches", Tier::Safe, &["Library/Caches"], None),
        (
            "homebrew-cache",
            Tier::Safe,
            &["Library/Caches/Homebrew"],
            None,
        ),
        ("user-logs", Tier::Safe, &["Library/Logs"], None),
        ("trash", Tier::Safe, &[".Trash"], None),
        (
            "xcode-derived-data",
            Tier::Safe,
            &["Library/Developer/Xcode/DerivedData"],
            None,
        ),
        (
            "cargo-cache",
            Tier::Safe,
            &[".cargo/registry/cache", ".cargo/registry/src", ".cargo/git"],
            None,
        ),
        ("npm-cache", Tier::Safe, &[".npm/_cacache"], None),
        (
            "xcode-archives",
            Tier::Caution,
            &["Library/Developer/Xcode/Archives"],
            None,
        ),
        (
            "ios-device-support",
            Tier::Caution,
            &["Library/Developer/Xcode/iOS DeviceSupport"],
            None,
        ),
        (
            "coresimulator",
            Tier::Caution,
            &["Library/Developer/CoreSimulator/Devices"],
            None,
        ),
        ("old-downloads", Tier::Caution, &["Downloads"], Some(90)),
        (
            "ios-backups",
            Tier::ReportOnly,
            &["Library/Application Support/MobileSync/Backup"],
            None,
        ),
    ];

    // Act
    let table = builtin();

    // Assert
    let got_ids: Vec<&str> = table.iter().map(|r| r.id.as_str()).collect();
    let want_ids: Vec<&str> = spec.iter().map(|s| s.0).collect();
    assert_eq!(
        got_ids, want_ids,
        "the table must hold exactly the spec's rules, in spec order"
    );
    for (rule, (id, tier, roots, days)) in table.iter().zip(spec) {
        assert_eq!(rule.tier, tier, "{id}: tier");
        let got_roots: Vec<&Path> = rule.roots.iter().map(PathBuf::as_path).collect();
        let want_roots: Vec<&Path> = roots.iter().map(Path::new).collect();
        assert_eq!(got_roots, want_roots, "{id}: roots");
        assert_eq!(
            rule.min_age,
            days.map(|d| Duration::from_secs(d * 86_400)),
            "{id}: min_age"
        );
        if id == "user-logs" {
            let excludes: BTreeSet<&Path> = rule.excludes.iter().map(PathBuf::as_path).collect();
            let want: BTreeSet<&Path> = [
                Path::new("Library/Logs/mac-cleaner"),
                Path::new("Library/Logs/mac-cleaner-dev"),
            ]
            .into();
            assert_eq!(
                excludes, want,
                "user-logs must exclude the tool's own log directories (never reclaimable)"
            );
        } else if id != "user-caches" {
            assert!(
                rule.excludes.is_empty(),
                "{id}: the spec lists no excludes, got {:?}",
                rule.excludes
            );
        }
    }
}

mod safety {
    use super::*;

    /// kebab-case: lowercase ASCII words (digits allowed) joined by single dashes.
    fn is_kebab(id: &str) -> bool {
        !id.is_empty()
            && id.split('-').all(|w| {
                !w.is_empty()
                    && w.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
    }

    /// # Design promise
    /// AC-002-11 / INV-05 / INV-06: over the whole table, ids are unique kebab-case; every rule has
    /// a non-empty explanation; roots are relative to HOME and clean; every root is admitted by the
    /// `SafetyGuard` for a sample home (so no root is, contains, or sits below a deny-listed path,
    /// and none is a symlink); `Report-only` rules are not deletable; no root is shared between two
    /// rules.
    ///
    /// # Scenario (Given)
    /// The built-in table; a guard for home `/Users/u`; a fake filesystem in which every root
    /// exists as a directory (so the lstat-based checks run too).
    ///
    /// # Action (When)
    /// Check each invariant for every rule/root, using `admit_root` as the oracle for the deny list.
    ///
    /// # Expected (Then)
    /// All hold; the table is non-empty (an empty table must not pass vacuously).
    ///
    /// # Must never
    /// Admit a root such as `Documents`, `.ssh` or `Library/Keychains` (or any ancestor, e.g. the
    /// empty root = HOME); mark a Report-only rule deletable.
    ///
    /// # Would catch
    /// A copy-paste id, `Old_Downloads`, a root of `""` or `Library` (ancestor of denied paths), an
    /// absolute root escaping HOME, `deletable: true` on `ios-backups`, two rules claiming the same
    /// root (ambiguous ownership).
    ///
    /// # Why this test (not redundant)
    /// The data-driven validity test required by AC-002-11; the pin test above compares against the
    /// spec text instead.
    #[test]
    fn ac_002_11_table_invariants_hold_for_every_rule() {
        // Arrange
        let table = builtin();
        let guard = SafetyGuard::new(&HomeDir::new(HOME));
        let mut builder = FakeFs::builder();
        for rule in &table {
            for root in &rule.roots {
                builder = builder.dir(Path::new(HOME).join(root));
            }
        }
        let fs = builder.build();

        // Act + Assert
        assert!(!table.is_empty(), "the built-in table must not be empty");
        let mut ids = BTreeSet::new();
        let mut roots_seen = BTreeSet::new();
        for rule in &table {
            assert!(is_kebab(&rule.id), "id `{}` must be kebab-case", rule.id);
            assert!(
                ids.insert(rule.id.clone()),
                "id `{}` is duplicated",
                rule.id
            );
            assert!(
                !rule.explain.trim().is_empty(),
                "{}: explain must not be empty",
                rule.id
            );
            assert!(
                !rule.roots.is_empty(),
                "{}: a rule needs at least one root",
                rule.id
            );
            if rule.tier == Tier::ReportOnly {
                assert!(
                    !rule.deletable,
                    "INV-05: Report-only rule `{}` must not be deletable",
                    rule.id
                );
            }
            for root in &rule.roots {
                assert!(
                    root.is_relative()
                        && !root.as_os_str().is_empty()
                        && !root
                            .components()
                            .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
                    "{}: root {root:?} must be a clean path relative to HOME",
                    rule.id
                );
                assert!(
                    roots_seen.insert(root.clone()),
                    "{}: root {root:?} is also a root of another rule (ambiguous ownership)",
                    rule.id
                );
                let abs = Path::new(HOME).join(root);
                let verdict = guard.admit_root(&fs, &abs);
                assert!(
                    verdict
                        .as_ref()
                        .is_ok_and(cleaner_core::safety::SafePath::exists),
                    "INV-06: {}: root {abs:?} must be admitted by SafetyGuard::admit_root, got {verdict:?}",
                    rule.id
                );
            }
        }
    }

    /// # Design promise
    /// AC-002-9 / AC-002-22: for the real table, a path is claimed by the most specific rule root
    /// containing it, matching is component-wise, and the tool's own log directories are claimed by
    /// nobody (never reported as reclaimable).
    ///
    /// # Scenario (Given)
    /// The built-in table and `(relative path, expected owner)` rows: `Caches/x` -> user-caches;
    /// `Caches/Homebrew` (a root) and `Caches/Homebrew/x` -> homebrew-cache; the root `Library/Caches`
    /// itself -> user-caches; `Library/Caches-old/x` -> nobody (component-wise); `Library/Logs/x` ->
    /// user-logs; `Library/Logs/mac-cleaner/a`, `.../mac-cleaner`, `.../mac-cleaner-dev/b` -> nobody;
    /// `Library/Logs/mac-cleaner-extra/c` and `Library/Logs/mac-cleaner.txt` -> user-logs
    /// (look-alikes); `.cargo/git/o`, `.cargo/registry/cache/c`, `.cargo/registry/src/s` ->
    /// cargo-cache; `.cargo/registry/index/i` and `.cargo/registry/cache-x/y` -> nobody; `Library` ->
    /// nobody (an ancestor of a root); `.Trash/t` -> trash; `Downloads/d` -> old-downloads.
    ///
    /// # Action (When)
    /// `owner_of(&table, rel)` per row.
    ///
    /// # Expected (Then)
    /// Each row's expected owner id (or `None`).
    ///
    /// # Must never
    /// Claim by string prefix; double-claim (a function returns one owner by construction, so the
    /// nested rows prove the parent does not also match); claim the tool's own logs.
    ///
    /// # Would catch
    /// `starts_with` on strings (`Caches-old`), first-match instead of longest-match (Homebrew
    /// credited to user-caches: double counting), ignoring `excludes`.
    ///
    /// # Why this test (not redundant)
    /// Pins the claim logic on the real data; the next test pins the logic's own classes on
    /// synthetic rules.
    #[test]
    fn ac_002_9_owner_of_follows_the_spec_table() {
        // Arrange
        let table = builtin();
        let rows: [(&str, Option<&str>); 20] = [
            ("Library/Caches/x", Some("user-caches")),
            ("Library/Caches", Some("user-caches")),
            ("Library/Caches/Homebrew", Some("homebrew-cache")),
            ("Library/Caches/Homebrew/x", Some("homebrew-cache")),
            ("Library/Caches-old/x", None),
            ("Library/Logs/x", Some("user-logs")),
            ("Library/Logs/mac-cleaner", None),
            ("Library/Logs/mac-cleaner/a", None),
            ("Library/Logs/mac-cleaner-dev/b", None),
            ("Library/Logs/mac-cleaner-extra/c", Some("user-logs")),
            ("Library/Logs/mac-cleaner.txt", Some("user-logs")),
            (".cargo/git/o", Some("cargo-cache")),
            (".cargo/registry/cache/c", Some("cargo-cache")),
            (".cargo/registry/src/s", Some("cargo-cache")),
            (".cargo/registry/index/i", None),
            (".cargo/registry/cache-x/y", None),
            ("Library", None),
            (".Trash/t", Some("trash")),
            ("Downloads/d", Some("old-downloads")),
            ("Documents/x", None),
        ];

        for (rel, want) in rows {
            // Act
            let got = owner(&table, rel);

            // Assert
            assert_eq!(got, want, "AC-002-9/22: owner of `{rel}`");
        }
    }

    /// # Design promise
    /// `owner_of` contract: longest matching root wins regardless of table order; ties go to the
    /// earlier rule; an excluded subtree is not claimed by the excluding rule but an enclosing rule
    /// with a shorter root may claim it; the root itself is claimed.
    ///
    /// # Scenario (Given)
    /// Synthetic rules `outer` (root `a`), `mid` (`a/b`), `inner` (`a/b/c`); `twin1` and `twin2`
    /// (both root `t`: a tie); `ex` (root `e`, excludes `e/skip`); `host` (root `h`, excludes `h/x`)
    /// and `guest` (root `h/x/y`, inside host's excluded subtree). Every row is evaluated for the
    /// table order and for the nested rules reversed.
    ///
    /// # Action (When)
    /// `owner_of` per row.
    ///
    /// # Expected (Then)
    /// `a/q` -> outer; `a/b/q` -> mid; `a/b/c/q` -> inner (in both table orders); `a/bb/q` -> outer
    /// (component-wise, not mid); `a` -> outer (the root itself is claimed); `t/q` -> twin1 (earlier
    /// rule wins the tie); `e/skip/q` -> nobody (excluded, nothing encloses it); `e/ok` -> ex;
    /// `h/x/z` -> nobody (host excludes it); `h/x/y/z` -> guest; `h/other` -> host.
    /// **Flagged for orchestrator ratification:** an excluded subtree may be claimed by a rule
    /// whose shorter root encloses it (documented on `owner_of`, not exercised: no built-in rule
    /// combines the two).
    ///
    /// # Must never
    /// Depend on table order for nested roots; claim an excluded path for the excluding rule.
    ///
    /// # Would catch
    /// First-match-wins, `starts_with` on strings, ignoring `excludes`, a tie that depends on
    /// iteration order.
    ///
    /// # Why this test (not redundant)
    /// Covers the logic classes independent of the built-in data (which may change by amendment).
    #[test]
    fn ac_002_9_owner_of_logic_longest_root_component_wise_excludes_and_ties() {
        // Arrange
        let mut ex = Rule::new("ex", Tier::Safe, &["e"]);
        ex.excludes = vec!["e/skip".into()];
        let mut host = Rule::new("host", Tier::Safe, &["h"]);
        host.excludes = vec!["h/x".into()];
        let nested = [
            Rule::new("outer", Tier::Safe, &["a"]),
            Rule::new("mid", Tier::Safe, &["a/b"]),
            Rule::new("inner", Tier::Safe, &["a/b/c"]),
        ];
        let others = [
            Rule::new("twin1", Tier::Safe, &["t"]),
            Rule::new("twin2", Tier::Safe, &["t"]),
            ex,
            host,
            Rule::new("guest", Tier::Safe, &["h/x/y"]),
        ];
        let forward: Vec<Rule> = nested.iter().chain(others.iter()).cloned().collect();
        let reversed: Vec<Rule> = nested.iter().rev().chain(others.iter()).cloned().collect();
        let rows: [(&str, Option<&str>); 11] = [
            ("a/q", Some("outer")),
            ("a/b/q", Some("mid")),
            ("a/b/c/q", Some("inner")),
            ("a/bb/q", Some("outer")),
            ("t/q", Some("twin1")),
            ("e/skip/q", None),
            ("e/ok", Some("ex")),
            ("h/x/z", None),
            ("h/x/y/z", Some("guest")),
            ("h/other", Some("host")),
            ("a", Some("outer")),
        ];

        for (label, rules) in [
            ("table order", &forward),
            ("nested rules reversed", &reversed),
        ] {
            for (rel, want) in rows {
                // Act
                let got = owner(rules, rel);

                // Assert
                assert_eq!(got, want, "owner_of({rel}) with {label}");
            }
        }
    }
}
