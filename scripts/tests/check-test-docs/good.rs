//! Fixture: a compliant test module. `scripts/check-test-docs.sh` must accept it.

#[cfg(test)]
mod tests {
    /// # Design promise
    /// AC-000-1: the fixture shows a fully documented test.
    ///
    /// # Scenario (Given)
    /// Two equal integers.
    ///
    /// # Action (When)
    /// They are compared.
    ///
    /// # Expected (Then)
    /// Equality holds, because the operands are identical.
    ///
    /// # Must never
    /// n/a
    ///
    /// # Would catch
    /// A checker that rejects compliant docs.
    ///
    /// # Why this test (not redundant)
    /// It is the only compliant sample.
    #[test]
    #[ignore = "fixture only"]
    fn ac_000_1_documented_test_with_messages() {
        let v = vec![1, 2, 3];
        assert!(!v.is_empty(), "AC-000-1: vec must not be empty");
        assert_eq!(
            v.len(),
            3,
            "AC-000-1: length is {} not 3, with a comma, in the message",
            v.len()
        );
        assert_ne!(v[0], v[1], "AC-000-1: first two differ");
        debug_assert!(v.iter().all(|a| *a > 0), "AC-000-1: all positive");
        // assert!(false) in a comment is ignored, as is "assert_eq!(1, 1)" in a string.
        let _s = "assert!(true)";
    }

    proptest::proptest! {
        /// # Design promise
        /// Property tests inside `proptest!` are documented too.
        ///
        /// # Scenario (Given)
        /// Any u8.
        ///
        /// # Action (When)
        /// Widened to u16.
        ///
        /// # Expected (Then)
        /// Value is preserved.
        ///
        /// # Must never
        /// Truncate.
        ///
        /// # Would catch
        /// A lossy cast.
        ///
        /// # Why this test (not redundant)
        /// Only property sample.
        fn prop_widening_preserves(x in 0u8..) {
            assert_eq!(u16::from(x) as u8, x, "widening must preserve value {}", x);
        }
    }

    // Not a test: helpers are not checked.
    fn helper() {
        assert!(true);
    }
}
