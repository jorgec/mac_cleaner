//! Production run identifiers (spec 002 AC-002-17: `run_id` is a ULID/UUID; INV-11).
//!
//! # Worksheet - `ids::UlidRunIds::next_run_id`
//! ```text
//! Function:        cleaner_cli::ids::UlidRunIds (cleaner_core::ports::RunIds)
//! Contract:        every id is 26 characters of Crockford base32 (0-9 A-H J K M N P-T V-Z, upper case);
//!                  ids from one generator are unique and strictly increasing as strings, even when
//!                  produced within the same millisecond (so logs sort by run). (AC-002-17)
//! Equivalence classes: one (no input); burst of many ids in the same millisecond
//! Boundaries:      length exactly 26; the Crockford alphabet excludes I, L, O, U
//! Must-never:      repeat an id; go backwards within one process; use a non-sortable/lower-case form
//! Selected tests:  ac_002_17_run_ids_are_26_char_crockford_unique_and_strictly_increasing
//! Deliberately not tested: the timestamp prefix value (library behavior); other injected generators
//!                  (tests use `SequentialRunIds` from the testkit).
//! ```

use cleaner_cli::ids::UlidRunIds;
use cleaner_core::ports::RunIds;

/// # Design promise
/// AC-002-17 / INV-11: production run ids are ULIDs (26-char Crockford base32) that are unique and sort
/// in creation order, so `run_id` values and audit files can be ordered and correlated.
///
/// # Scenario (Given)
/// One generator asked for 1000 ids in a tight loop (many fall into the same millisecond).
///
/// # Action (When)
/// `next_run_id()` 1000 times.
///
/// # Expected (Then)
/// Each id is 26 characters from `0123456789ABCDEFGHJKMNPQRSTVWXYZ`; each id is strictly greater (as a
/// string) than the previous one, which also proves uniqueness.
///
/// # Must never
/// Produce a duplicate or an id that sorts before its predecessor within the process.
///
/// # Would catch
/// A constant (the stub), a non-monotonic `Ulid::new()` per call (random order within a millisecond),
/// lower-case or UUID output, a wrong length.
///
/// # Why this test (not redundant)
/// The only test of the production generator; every other test injects sequential ids.
#[test]
fn ac_002_17_run_ids_are_26_char_crockford_unique_and_strictly_increasing() {
    // Arrange
    let ids = UlidRunIds::new();
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut previous: Option<String> = None;

    for n in 0..1000 {
        // Act
        let id = ids.next_run_id().as_str().to_owned();

        // Assert
        assert_eq!(id.len(), 26, "id #{n} `{id}`: a ULID is 26 characters");
        assert!(
            id.chars().all(|c| alphabet.contains(c)),
            "id #{n} `{id}`: only upper-case Crockford base32 characters are allowed"
        );
        if let Some(prev) = &previous {
            assert!(
                id > *prev,
                "id #{n} `{id}` must sort after the previous `{prev}` (monotonic, unique)"
            );
        }
        previous = Some(id);
    }
}
