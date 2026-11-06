//! Fixture: a test whose rustdoc lacks `# Would catch` and `# Why this test (not redundant)`.

#[cfg(test)]
mod tests {
    /// # Design promise
    /// Something.
    ///
    /// # Scenario (Given)
    /// Something.
    ///
    /// # Action (When)
    /// Something.
    ///
    /// # Expected (Then)
    /// Something.
    ///
    /// # Must never
    /// Something.
    #[test]
    fn ac_000_2_incomplete_docs() {
        assert!(true, "has a message, so only the docs are wrong");
    }

    #[test]
    fn ac_000_3_no_docs_at_all() {
        assert!(true, "message present");
    }
}
