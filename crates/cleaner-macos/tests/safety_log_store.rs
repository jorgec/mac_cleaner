//! `FileLogStore` (the sole phase-1 mutation port) on a real temp directory: spec 001 AC-001-14.
//! Tagged `safety` because `remove` is a deletion primitive (INV-06/INV-07: it must never act
//! outside its own directory).
//!
//! # Worksheet - `FileLogStore::{list, remove}`
//! ```text
//! Function:        cleaner_macos::FileLogStore::new(dir) + LogStore::{list, remove(name)}
//! Contract:        list -> names of the entries directly in dir; remove(name) unlinks that one
//!                  entry; any name that is empty/`.`/`..`/absolute/contains `/` -> Err(InvalidInput)
//!                  and NOTHING is removed. (AC-001-14, INV-07 spirit)
//! Equivalence classes: plain existing name | traversal names (`../x`, absolute, `.`, `..`, `a/b`, "")
//! Boundaries:      plain name vs name containing a separator
//! Must-never:      removing anything outside `dir` (or `dir` itself)
//! Selected tests:  list_and_remove_act_on_exactly_the_named_entry,
//!                  remove_refuses_names_that_could_leave_the_directory
//! Deliberately not tested: pruning policy (core, audit_retention.rs); remove of a directory entry.
//! ```

mod safety {
    use std::fs::{self, File};
    use std::io::{ErrorKind, Write as _};

    use cleaner_core::ports::LogStore;
    use cleaner_macos::FileLogStore;

    /// Create `path` as a small regular file.
    fn touch(path: &std::path::Path) {
        File::create(path)
            .and_then(|mut f| f.write_all(b"x"))
            .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    }

    /// # Design promise
    /// AC-001-14: the adapter lists entry *names* and removes exactly the one named entry.
    ///
    /// # Scenario (Given)
    /// A temp log dir with `audit-2020-01-01.jsonl` and `notes.txt`.
    ///
    /// # Action (When)
    /// `list()`, then `remove("audit-2020-01-01.jsonl")`, then `list()` again.
    ///
    /// # Expected (Then)
    /// First list (sorted) is both names; the remove is `Ok`; the file is gone, `notes.txt` and the
    /// directory remain.
    ///
    /// # Must never
    /// Remove a sibling or the directory.
    ///
    /// # Would catch
    /// `remove_dir_all(dir)`, listing full paths instead of names.
    ///
    /// # Why this test (not redundant)
    /// Adapter happy path; the next test covers hostile names.
    #[test]
    fn ac_001_14_list_and_remove_act_on_exactly_the_named_entry() {
        // Arrange
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("logs");
        fs::create_dir_all(&dir).expect("mkdir");
        touch(&dir.join("audit-2020-01-01.jsonl"));
        touch(&dir.join("notes.txt"));
        let store = FileLogStore::new(&dir);

        // Act
        let mut before = store.list().expect("list");
        before.sort();
        let removed = store.remove("audit-2020-01-01.jsonl");
        let mut after = store.list().expect("list again");
        after.sort();

        // Assert
        assert_eq!(
            before,
            vec!["audit-2020-01-01.jsonl".to_owned(), "notes.txt".to_owned()],
            "names, not paths"
        );
        assert!(
            removed.is_ok(),
            "removing a plain existing name must succeed: {removed:?}"
        );
        assert_eq!(
            after,
            vec!["notes.txt".to_owned()],
            "only the named entry is gone"
        );
        assert!(dir.is_dir(), "the log directory itself must remain");
    }

    /// # Design promise
    /// AC-001-14 / INV-07 spirit: `remove` can never delete outside its directory, whatever name it is
    /// handed.
    ///
    /// # Scenario (Given)
    /// `<tmp>/victim.txt` sits next to the log dir `<tmp>/logs` (which holds `keep.txt`). Names:
    /// `../victim.txt`, the absolute path of the victim, `.`, `..`, `sub/keep.txt`, and the empty
    /// string.
    ///
    /// # Action (When)
    /// `remove(name)` for each.
    ///
    /// # Expected (Then)
    /// Each returns `Err` of kind `InvalidInput`; the victim, `keep.txt` and the directory all still
    /// exist.
    ///
    /// # Must never
    /// Remove the victim (outside the dir), the dir itself, or anything else.
    ///
    /// # Would catch
    /// `dir.join(name)` with an absolute `name` (replaces the base!), or `..` traversal.
    ///
    /// # Why this test (not redundant)
    /// The only must-never coverage of the one deletion primitive in phase 1.
    #[test]
    fn ac_001_14_remove_refuses_names_that_could_leave_the_directory() {
        // Arrange
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("logs");
        fs::create_dir_all(&dir).expect("mkdir");
        touch(&dir.join("keep.txt"));
        let victim = tmp.path().join("victim.txt");
        touch(&victim);
        let store = FileLogStore::new(&dir);
        let abs = victim.to_string_lossy().into_owned();
        let names = ["../victim.txt", abs.as_str(), ".", "..", "sub/keep.txt", ""];

        for name in names {
            // Act
            let got = store.remove(name);

            // Assert
            let err = got.expect_err(&format!("name {name:?} must be refused"));
            assert_eq!(
                err.kind(),
                ErrorKind::InvalidInput,
                "name {name:?}: refusal must be InvalidInput"
            );
            assert!(
                victim.exists(),
                "INV-07: file outside the log dir was removed via name {name:?}"
            );
            assert!(
                dir.join("keep.txt").exists(),
                "name {name:?}: file inside the dir was removed"
            );
        }
    }
}
