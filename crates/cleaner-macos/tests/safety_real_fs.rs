//! `RealFs` adapter on a real temp directory (INV-07/INV-08 adapter contract for the `Fs` port).
//!
//! # Worksheet - `RealFs::lstat`
//! ```text
//! Function:        cleaner_macos::RealFs::lstat (cleaner_core::ports::Fs)
//! Contract:        symlink_metadata semantics: kind of the final component WITHOUT following it
//!                  (live, dangling and self-looping links are `Symlink`); `dev` is st_dev; errors
//!                  are the raw OS errors (ENOENT -> NotFound). (INV-07, INV-08)
//! Equivalence classes: file | dir | symlink (live, dangling, loop) | missing
//! Boundaries:      symlink as final component
//! Must-never:      following a symlink (would report the target's kind/device)
//! Selected tests:  lstat_reports_kind_and_device_and_never_follows_symlinks
//! Deliberately not tested: `Other` kinds (sockets/fifos) - same std mapping; intermediate-symlink
//!                  following is OS behavior, modeled by the FakeFs sanity test.
//! ```

mod safety {
    use std::fs::{self, File};
    use std::io::ErrorKind;
    use std::os::unix::fs::{MetadataExt, symlink};

    use cleaner_core::ports::{FileKind, Fs};
    use cleaner_macos::RealFs;

    /// # Design promise
    /// INV-07 / INV-08: the real adapter reports what is *at* the path (never what a symlink points
    /// to) and the real `st_dev`.
    ///
    /// # Scenario (Given)
    /// In a temp dir: a file, a directory, a live symlink to the directory, a dangling symlink, and
    /// a self-referencing symlink loop.
    ///
    /// # Action (When)
    /// `RealFs.lstat` on each, plus on a missing name.
    ///
    /// # Expected (Then)
    /// File -> `File`, dir -> `Dir`, the three links -> `Symlink` (a following implementation would
    /// say `Dir`, fail with ENOENT, or fail with ELOOP); `dev` equals `std::fs::metadata().dev()`
    /// of the directory; missing -> `ErrorKind::NotFound`.
    ///
    /// # Must never
    /// Follow a final-component symlink.
    ///
    /// # Would catch
    /// `std::fs::metadata` instead of `symlink_metadata`; hard-coded device.
    ///
    /// # Why this test (not redundant)
    /// Only real-adapter coverage of the `Fs` port; all guard logic is tested against `FakeFs`.
    #[test]
    fn inv_07_lstat_reports_kind_and_device_and_never_follows_symlinks() {
        // Arrange
        let tmp = tempfile::tempdir().expect("temp dir");
        let p = tmp.path();
        File::create(p.join("file")).expect("file");
        fs::create_dir(p.join("dir")).expect("dir");
        symlink(p.join("dir"), p.join("live")).expect("live link");
        symlink(p.join("nowhere"), p.join("dangling")).expect("dangling link");
        symlink(p.join("loop"), p.join("loop")).expect("loop link");

        // Act + Assert
        let kinds = [
            ("file", FileKind::File),
            ("dir", FileKind::Dir),
            ("live", FileKind::Symlink),
            ("dangling", FileKind::Symlink),
            ("loop", FileKind::Symlink),
        ];
        for (name, want) in kinds {
            let md = RealFs
                .lstat(&p.join(name))
                .unwrap_or_else(|e| panic!("lstat {name}: {e}"));
            assert_eq!(
                md.kind, want,
                "{name}: wrong kind (a symlink must not be followed)"
            );
        }
        let dir_dev = fs::metadata(p.join("dir")).expect("stat dir").dev();
        let md = RealFs.lstat(&p.join("dir")).expect("lstat dir");
        assert_eq!(md.dev, dir_dev, "dev must be the real st_dev");
        let missing = RealFs
            .lstat(&p.join("missing"))
            .expect_err("missing path must error");
        assert_eq!(
            missing.kind(),
            ErrorKind::NotFound,
            "ENOENT must be surfaced unchanged"
        );
    }
}
