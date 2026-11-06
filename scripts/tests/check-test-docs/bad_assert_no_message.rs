//! Fixture: fully documented tests whose assertions lack messages.

#[cfg(test)]
mod tests {
    /// # Design promise
    /// x.
    ///
    /// # Scenario (Given)
    /// x.
    ///
    /// # Action (When)
    /// x.
    ///
    /// # Expected (Then)
    /// x.
    ///
    /// # Must never
    /// x.
    ///
    /// # Would catch
    /// x.
    ///
    /// # Why this test (not redundant)
    /// x.
    #[test]
    fn ac_000_4_asserts_without_messages() {
        let v = vec![1, 2];
        assert!(!v.is_empty());
        assert_eq!(
            v.len(),
            2
        );
        assert_ne!(v[0], v[1], "this one is fine");
        debug_assert!(v.len() == 2);
    }
}
