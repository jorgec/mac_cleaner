//! Rule selectors of `cleaner scan` (spec 002 AC-002-14; INV-02). Pure: operates on the built-in
//! rule table and returns rules; nothing is scanned or created here (the exit-code-2 plumbing and
//! "no log created" are in `scan_cli.rs`).
//!
//! # Worksheet - `select::select_rules`
//! ```text
//! Function:        cleaner_cli::select::select_rules(all, ids, tier) -> Result<Vec<Rule>, SelectError>
//! Contract:        none -> all rules; ids -> those rules; tier -> that tier; both -> intersection;
//!                  result always in table order, deduplicated; ids are case-sensitive; an unknown id
//!                  -> UnknownRule{id, valid = every table id} (checked first), whose Display names the
//!                  id and lists every valid id; valid-but-disjoint selectors -> NoMatch. (AC-002-14)
//! Equivalence classes: no selectors | ids (ordered/repeated) | tier (each of 3) | ids+tier overlapping
//!                  | ids+tier disjoint | unknown id | case-different id
//! Boundaries:      empty ids vs one id; intersection empty vs non-empty
//! Must-never:      select anything by default beyond "scan everything" (scan is read-only); reorder
//!                  rules (hardlink attribution depends on table order); accept a near-miss id
//! Selected tests:  ac_002_14_selectors_narrow_in_table_order_and_reject_unknown_or_disjoint_combinations
//! Deliberately not tested: clap's own parsing of `--tier bogus` (library behavior; the exit code and
//!                  listing of valid tiers are checked through the binary).
//! ```

use cleaner_cli::select::{SelectError, select_rules};
use cleaner_core::rules::{Tier, builtin};

/// Expected outcome of a selection: the ids, or the error.
type Want = Result<Vec<String>, SelectError>;

/// Rule ids of a selection, in order.
fn ids(rules: &[cleaner_core::rules::Rule]) -> Vec<String> {
    rules.iter().map(|r| r.id.clone()).collect()
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// # Design promise
/// AC-002-14 / INV-02: selectors only *narrow* the scan, in table order; unknown ids and combinations
/// that match nothing are refused with a message that lists the valid choices; no selectors means
/// "scan everything" (permitted because a scan is read-only) and marks nothing selected.
///
/// # Scenario (Given)
/// The built-in table (12 rules). Rows: no selectors; `trash,user-caches,trash` (out of order and
/// repeated); `--tier report-only`; `--tier caution`; `user-caches` + `safe` (overlap); `user-caches` +
/// `caution` (disjoint); `no-such-rule`; `USER-CACHES` (case); `user-caches,no-such-rule` (unknown beats
/// valid).
///
/// # Action (When)
/// `select_rules(builtin(), ids, tier)` per row.
///
/// # Expected (Then)
/// All 12 ids in table order; `[user-caches, trash]`; `[ios-backups]`; the four Caution rules in table
/// order (`xcode-archives, ios-device-support, coresimulator, old-downloads`); `[user-caches]`;
/// `Err(NoMatch)`; `Err(UnknownRule{id:"no-such-rule"})`; `Err(UnknownRule{id:"USER-CACHES"})`;
/// `Err(UnknownRule{id:"no-such-rule"})`. Every `UnknownRule.valid` equals the 12 table ids and its
/// message contains the bad id and every valid id; the `NoMatch` message is non-empty.
///
/// # Must never
/// Change the order of rules; accept a case-different or partial id; return an empty scan silently
/// (a typo must not look like "nothing to reclaim").
///
/// # Would catch
/// Selecting in flag order (hardlink bytes would move between rules), union instead of intersection,
/// prefix/case-insensitive matching, swallowing unknown ids, an error message without the valid list
/// (the user cannot fix the command).
///
/// # Why this test (not redundant)
/// The only test of selection logic; the CLI test only proves it is wired to exit code 2.
#[test]
fn ac_002_14_selectors_narrow_in_table_order_and_reject_unknown_or_disjoint_combinations() {
    // Arrange
    let all_ids = ids(&builtin());
    assert_eq!(
        all_ids.len(),
        12,
        "the built-in table has twelve rules (spec 002)"
    );
    let unknown = |id: &str| -> Want {
        Err(SelectError::UnknownRule {
            id: id.to_owned(),
            valid: all_ids.clone(),
        })
    };
    let rows: Vec<(&str, Vec<String>, Option<Tier>, Want)> = vec![
        ("no selectors", vec![], None, Ok(all_ids.clone())),
        (
            "ids out of order and repeated",
            strings(&["trash", "user-caches", "trash"]),
            None,
            Ok(strings(&["user-caches", "trash"])),
        ),
        (
            "tier report-only",
            vec![],
            Some(Tier::ReportOnly),
            Ok(strings(&["ios-backups"])),
        ),
        (
            "tier caution",
            vec![],
            Some(Tier::Caution),
            Ok(strings(&[
                "xcode-archives",
                "ios-device-support",
                "coresimulator",
                "old-downloads",
            ])),
        ),
        (
            "id and tier overlap",
            strings(&["user-caches"]),
            Some(Tier::Safe),
            Ok(strings(&["user-caches"])),
        ),
        (
            "id and tier disjoint",
            strings(&["user-caches"]),
            Some(Tier::Caution),
            Err(SelectError::NoMatch),
        ),
        (
            "unknown id",
            strings(&["no-such-rule"]),
            None,
            unknown("no-such-rule"),
        ),
        (
            "case-different id",
            strings(&["USER-CACHES"]),
            None,
            unknown("USER-CACHES"),
        ),
        (
            "unknown id next to a valid one",
            strings(&["user-caches", "no-such-rule"]),
            None,
            unknown("no-such-rule"),
        ),
    ];

    for (name, selected, tier, want) in rows {
        // Act
        let got = select_rules(builtin(), &selected, tier);

        // Assert
        match (&got, &want) {
            (Ok(rules), Ok(want_ids)) => {
                assert_eq!(
                    &ids(rules),
                    want_ids,
                    "{name}: selected ids, in table order"
                );
            }
            (Err(e), Err(want_err)) => {
                assert_eq!(e, want_err, "{name}: error variant and payload");
                let message = e.to_string();
                match e {
                    SelectError::UnknownRule { id, valid } => {
                        assert!(
                            message.contains(id.as_str())
                                && valid.iter().all(|v| message.contains(v.as_str())),
                            "{name}: the message must name `{id}` and list every valid id: {message:?}"
                        );
                    }
                    SelectError::NoMatch => {
                        assert!(!message.is_empty(), "{name}: NoMatch needs an explanation");
                    }
                }
            }
            _ => panic!("{name}: expected {want:?}, got {:?}", got.map(|r| ids(&r))),
        }
    }
}
