//! Safety regression suite for `SafetyGuard` (spec 001 AC-001-1 .. AC-001-10; INV-06, INV-07,
//! INV-08, INV-13). Everything lives in `mod safety` so the CI filter `test(safety)` matches.
//! All filesystem state is the in-memory `FakeFs`; nothing touches the real machine (INV-15).
//!
//! # Worksheet 1 - `SafetyGuard::admit`
//! ```text
//! Function:        cleaner_core::safety::SafetyGuard::admit(fs, root, candidate)
//! Contract:        Ok(SafePath{normalized path, is_symlink}) only when candidate is a strict
//!                  component-wise descendant of root, not denied, not an ancestor of a denied
//!                  path, no symlink among the parents between root and candidate, root not a
//!                  symlink, same device as root; otherwise Err(Denied{kind, path=candidate}).
//!                  Verdict precedence: syntax -> deny list -> containment -> fs checks.
//!                  Lexical verdicts perform ZERO Fs calls; fs checks re-run on every call;
//!                  any Fs error is Err(Io). (AC-001-1..10, INV-06/07/08/13)
//! Equivalence classes: relative/empty | has `..` | denied (entry, descendant, non-UTF-8, firmlink)
//!                  | ancestor of denied (even outside root) | outside root | root itself
//!                  | final symlink (live, dangling, loop, inside-root) | symlink parent (outside,
//!                  inside, loop) | symlinked root | cross-device | fs error | clean admit
//!                  (messy separators, hostile names)
//! Boundaries:      `Documents` vs `Documents-old`/`Documentsx`; `Caches` vs `Caches-old`;
//!                  candidate == root; symlink as LAST vs PARENT component; `...` vs `..`;
//!                  firmlink prefix vs no prefix; parent dev != child dev
//! Must-never:      Fs access for a lexical verdict; lstat below a symlink; caching a verdict;
//!                  Ok on any Fs error
//! Selected tests:  see the `ac_001_*` fns below (one per class group; tables for AC 1,2,3,4,5,7,10)
//! Deliberately not tested: the `Denied`/`DeniedKind` Display text (not a contract); the
//!                  "no remove/override API" half of AC-001-8 (compile-level; verified by review of
//!                  the public API); `/usr/local` exception (INV-06 wording is ambiguous, no
//!                  phase-1 rule needs it, see matrix open issues); `with_extra_denied` with
//!                  relative paths (unspecified, see matrix).
//! ```
//!
//! # Worksheet 2 - `safety::normalize`
//! ```text
//! Function:        cleaner_core::safety::normalize(&Path) -> PathBuf
//! Contract:        collapses `//`, `/./`, trailing `/`; strips every leading
//!                  `/System/Volumes/Data`; keeps `..`; idempotent; pure. (AC-001-3)
//! Equivalence classes: no firmlink | single prefix | repeated prefix | prefix hidden behind `.`/`//`
//! Boundaries:      `/System/Volumes/Data` alone -> `/`; `/System/Volumes/DataX` is not the prefix
//! Must-never:      change the guard verdict of a path except by removing the prefix
//! Selected tests:  ac_001_3_firmlink_prefix_is_treated_identically (examples),
//!                  ac_001_3_normalize_is_idempotent_and_never_flips_a_verdict (property)
//! Deliberately not tested: exact output for `..`-bearing input (guard rejects before use).
//! ```

mod safety {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::{Path, PathBuf};

    use cleaner_core::safety::{Denied, DeniedKind, HomeDir, SafePath, SafetyGuard, normalize};
    use cleaner_testkit::FakeFs;
    use proptest::prelude::*;

    const HOME: &str = "/Users/u";
    const CACHES: &str = "/Users/u/Library/Caches";
    const DATA: &str = "/System/Volumes/Data";

    /// Guard for the fake home `/Users/u`.
    fn guard() -> SafetyGuard {
        SafetyGuard::new(&HomeDir::new(HOME))
    }

    /// Reduce a verdict to `Ok(())` / `Err(kind)` so rows compare on the stable cause only.
    fn kind_of(r: &Result<SafePath, Denied>) -> Result<(), DeniedKind> {
        r.as_ref().map(|_| ()).map_err(|d| d.kind)
    }

    /// A tree with a plain cache app, so clean candidates can be admitted:
    /// `/Users/u/Library/Caches/app/x`.
    fn caches_tree() -> cleaner_testkit::FakeFsBuilder {
        FakeFs::builder().file(format!("{CACHES}/app/x"))
    }

    /// One table row: root, candidate, expected verdict.
    struct Row {
        name: &'static str,
        root: &'static str,
        cand: &'static str,
        want: Result<(), DeniedKind>,
    }

    /// Run every row against `fs`, asserting the verdict kind; for `Err` rows whose cause is
    /// lexical (everything except the fs-dependent kinds) also assert zero `Fs` calls.
    fn run_rows(fs: &FakeFs, rows: &[Row]) {
        run_rows_with(&guard(), fs, rows);
    }

    /// [`run_rows`] with an explicit guard (for tests that need a different home or extra entries).
    fn run_rows_with(g: &SafetyGuard, fs: &FakeFs, rows: &[Row]) {
        for row in rows {
            let before = fs.calls().len();
            let got = g.admit(fs, Path::new(row.root), Path::new(row.cand));
            assert_eq!(
                kind_of(&got),
                row.want,
                "row `{}`: wrong verdict for {:?}",
                row.name,
                row.cand
            );
            let lexical = matches!(
                row.want,
                Err(DeniedKind::NotAbsolute
                    | DeniedKind::Traversal
                    | DeniedKind::DenyListed
                    | DeniedKind::AncestorOfDenied
                    | DeniedKind::OutsideRoot)
            );
            if lexical {
                assert_eq!(
                    fs.calls().len(),
                    before,
                    "row `{}`: a lexical verdict must not touch the filesystem",
                    row.name
                );
            }
        }
    }

    /// The built-in deny list as written in INV-06, expanded for home `/Users/u`.
    const BUILTIN_DENIED: [&str; 14] = [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/private/var/db",
        "/Library/Apple",
        "/Users/u/Documents",
        "/Users/u/Desktop",
        "/Users/u/Pictures",
        "/Users/u/Library/Keychains",
        "/Users/u/Library/Mobile Documents",
        "/Users/u/Library/Messages",
        "/Users/u/.ssh",
        "/Users/u/.gnupg",
    ];

    /// # Design promise
    /// AC-001-1 / INV-06: every built-in deny entry, and everything below it, is refused as
    /// `DenyListed`, decided from the path text alone, and the error names the refused candidate.
    ///
    /// # Scenario (Given)
    /// Home `/Users/u`; an EMPTY fake filesystem (so any `Fs` call would fail loudly); for each of
    /// the 14 INV-06 entries E: the root is E's parent (a root that "would otherwise contain" E).
    ///
    /// # Action (When)
    /// `admit(root, c)` for c in { E, E/child, E/a/b }.
    ///
    /// # Expected (Then)
    /// Every verdict is `Err(DenyListed)` whose `path` equals the candidate as passed; zero `Fs`
    /// calls were made (the verdict is lexical).
    ///
    /// # Must never
    /// Touch the filesystem to reach a deny verdict; admit any entry or descendant.
    ///
    /// # Would catch
    /// A deny list that forgot one INV-06 entry (the table is the whole list), matched only the
    /// exact entry and not descendants, or stat'ed the path before deciding.
    ///
    /// # Why this test (not redundant)
    /// Covers the "denied" class for all entries at once; look-alike boundaries are in the next test.
    #[test]
    fn ac_001_1_every_builtin_entry_and_its_descendants_are_deny_listed() {
        // Arrange: empty fs; any lstat would be an error AND show up in `calls()`.
        let fs = FakeFs::builder().build();
        let g = guard();

        for entry in BUILTIN_DENIED {
            let root = Path::new(entry).parent().expect("entries are never `/`");
            for cand in [
                entry.to_owned(),
                format!("{entry}/child"),
                format!("{entry}/a/b"),
            ] {
                // Act
                let got = g.admit(&fs, root, Path::new(&cand));

                // Assert
                let denied = got.expect_err(&format!("INV-06: {cand} must be refused"));
                assert_eq!(denied.kind, DeniedKind::DenyListed, "{cand}: wrong cause");
                assert_eq!(
                    denied.path,
                    PathBuf::from(&cand),
                    "{cand}: error must name the candidate"
                );
            }
        }
        assert!(
            fs.calls().is_empty(),
            "deny verdicts must be decided without any Fs call"
        );
    }

    /// # Design promise
    /// AC-001-1 boundary: the deny list matches whole path components, not string prefixes.
    ///
    /// # Scenario (Given)
    /// `/Users/u/Documents-old/x`, `/Users/u/Documentsx` and `/Systems/x` exist as ordinary files;
    /// they share a string prefix with `Documents` / `/System` but are different components.
    ///
    /// # Action (When)
    /// `admit` each under the root that contains it.
    ///
    /// # Expected (Then)
    /// All three are admitted (`Ok`), because component-wise they are not denied.
    ///
    /// # Must never
    /// Refuse a legitimate sibling (over-blocking makes the tool useless and hides real denials).
    ///
    /// # Would catch
    /// `starts_with` on strings instead of `Path::starts_with` on components.
    ///
    /// # Why this test (not redundant)
    /// The only success-side boundary of the deny list; the previous test is all rejections.
    #[test]
    fn ac_001_1_lookalike_siblings_of_denied_names_are_not_denied() {
        // Arrange
        let fs = FakeFs::builder()
            .file("/Users/u/Documents-old/x")
            .file("/Users/u/Documentsx")
            .file("/Systems/x")
            .build();
        let rows = [
            Row {
                name: "Documents-old",
                root: "/Users/u",
                cand: "/Users/u/Documents-old/x",
                want: Ok(()),
            },
            Row {
                name: "Documentsx",
                root: "/Users/u",
                cand: "/Users/u/Documentsx",
                want: Ok(()),
            },
            Row {
                name: "Systems",
                root: "/",
                cand: "/Systems/x",
                want: Ok(()),
            },
        ];

        // Act + Assert
        run_rows(&fs, &rows);
    }

    /// # Design promise
    /// AC-001-2 / INV-06: an ancestor of a denied path can never be a candidate (removing it would
    /// remove the denied descendant), regardless of which root the caller names.
    ///
    /// # Scenario (Given)
    /// Root `/Users/u/Library/Caches` (so none of the candidates are even inside it, which pins the
    /// precedence deny-list > containment); empty fake fs.
    ///
    /// # Action (When)
    /// `admit` `/`, `/Users`, `/Users/u` (home itself), `/Users/u/Library`, `/Library`, `/private`,
    /// `/private/var`.
    ///
    /// # Expected (Then)
    /// Each is `Err(AncestorOfDenied)` (not `OutsideRoot`), with zero `Fs` calls.
    ///
    /// # Must never
    /// Admit `/` or `$HOME`; report a weaker kind that a caller might treat as "just skip".
    ///
    /// # Would catch
    /// Containment checked before the deny list; ancestors checked only for home-relative entries.
    ///
    /// # Why this test (not redundant)
    /// The only test of the ancestor class and of the verdict precedence.
    #[test]
    fn ac_001_2_ancestors_of_denied_paths_are_denied_even_outside_the_root() {
        // Arrange
        let fs = FakeFs::builder().build();
        let rows: Vec<Row> = [
            ("slash", "/"),
            ("users", "/Users"),
            ("home", "/Users/u"),
            ("home-library", "/Users/u/Library"),
            ("system-library-dir", "/Library"),
            ("private", "/private"),
            ("private-var", "/private/var"),
        ]
        .into_iter()
        .map(|(name, cand)| Row {
            name,
            root: CACHES,
            cand,
            want: Err(DeniedKind::AncestorOfDenied),
        })
        .collect();

        // Act + Assert
        run_rows(&fs, &rows);
    }

    /// # Design promise
    /// AC-001-2: a sibling of a denied path (`Library/Caches` next to `Library/Keychains`) is not an
    /// ancestor of anything denied and is admitted when otherwise valid.
    ///
    /// # Scenario (Given)
    /// Root `/Users/u/Library`; `/Users/u/Library/Caches` is an existing directory.
    ///
    /// # Action (When)
    /// `admit(root, /Users/u/Library/Caches)`.
    ///
    /// # Expected (Then)
    /// `Ok`, not a symlink.
    ///
    /// # Must never
    /// Refuse the sibling because its parent is an ancestor of a denied path.
    ///
    /// # Would catch
    /// An "ancestor" check implemented as `denied.starts_with(candidate.parent())`.
    ///
    /// # Why this test (not redundant)
    /// Success-side boundary of the ancestor rule.
    #[test]
    fn ac_001_2_sibling_of_a_denied_path_is_admitted() {
        // Arrange
        let fs = FakeFs::builder().dir(CACHES).build();

        // Act
        let got = guard().admit(&fs, Path::new("/Users/u/Library"), Path::new(CACHES));

        // Assert
        let safe = got.expect("Library/Caches is a legitimate candidate under Library");
        assert!(
            !safe.is_symlink(),
            "a real directory must not be flagged as a symlink"
        );
    }

    /// # Design promise
    /// AC-001-3 / INV-06: `/System/Volumes/Data/<p>` is judged exactly like `/<p>`, and the admitted
    /// path is reported in the normalized (prefix-free) form.
    ///
    /// # Scenario (Given)
    /// Tree `/Users/u/Library/Caches/app/x`. Rows: firmlinked denied path; firmlinked allowed path
    /// (must NOT be denied just because `/System` is on the deny list); both root and candidate
    /// firmlinked; the firmlink root `/System/Volumes/Data` itself.
    ///
    /// # Action (When)
    /// `admit` each row.
    ///
    /// # Expected (Then)
    /// Denied row -> `DenyListed`; allowed rows -> `Ok` with `path()` == `/Users/u/Library/Caches/app/x`;
    /// `/System/Volumes/Data` -> `AncestorOfDenied` (it normalizes to `/`).
    ///
    /// # Must never
    /// Let the firmlink spelling bypass the deny list, or over-deny an allowed path under it.
    ///
    /// # Would catch
    /// No normalization (bypass), or normalization after the deny check (over-deny via `/System`).
    ///
    /// # Why this test (not redundant)
    /// Concrete examples; the property below covers the algebra, not these expected verdicts.
    #[test]
    fn ac_001_3_firmlink_prefix_is_treated_identically() {
        // Arrange
        let fs = caches_tree().build();
        let g = guard();
        let want_path = format!("{CACHES}/app/x");
        let rows: [(&str, String, String, Result<&str, DeniedKind>); 4] = [
            (
                "denied-via-firmlink",
                HOME.to_owned(),
                format!("{DATA}{HOME}/Documents/x"),
                Err(DeniedKind::DenyListed),
            ),
            (
                "allowed-via-firmlink",
                CACHES.to_owned(),
                format!("{DATA}{CACHES}/app/x"),
                Ok(want_path.as_str()),
            ),
            (
                "both-firmlinked",
                format!("{DATA}{CACHES}"),
                format!("{DATA}{CACHES}/app/x"),
                Ok(want_path.as_str()),
            ),
            (
                "data-root-itself",
                CACHES.to_owned(),
                DATA.to_owned(),
                Err(DeniedKind::AncestorOfDenied),
            ),
        ];

        // Act + Assert
        for (name, root, cand, want) in rows {
            let got = g.admit(&fs, Path::new(&root), Path::new(&cand));
            match want {
                Ok(p) => {
                    let safe =
                        got.unwrap_or_else(|e| panic!("row `{name}`: expected Ok, got {e:?}"));
                    assert_eq!(
                        safe.path().as_os_str(),
                        Path::new(p).as_os_str(),
                        "row `{name}`: path must be normalized"
                    );
                }
                Err(kind) => assert_eq!(kind_of(&got), Err(kind), "row `{name}`: wrong verdict"),
            }
        }
    }

    /// Strategy: path components drawn from a small alphabet that hits the interesting syntax
    /// (firmlink words, deny-list words, `.`, `..`, empty = `//`).
    fn components() -> impl Strategy<Value = Vec<&'static str>> {
        prop::collection::vec(
            prop::sample::select(vec![
                "Users",
                "u",
                "Documents",
                "Library",
                "Caches",
                "System",
                "Volumes",
                "Data",
                "x",
                "",
                ".",
                "..",
                // AC-001-18 aliases and the entry they lead to (`/private/var/db`):
                "var",
                "tmp",
                "etc",
                "private",
                "db",
            ]),
            0..8,
        )
    }

    proptest! {
        // No on-disk regression file: failures print their minimal input, and tests never write
        // into the source tree (INV-15 spirit).
        #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

        /// # Design promise
        /// AC-001-3: `normalize` is idempotent; normalizing never changes the guard's verdict; and
        /// prefixing any absolute path with `/System/Volumes/Data` never changes its verdict - the
        /// firmlink prefix rule is the *only* thing that equates two spellings.
        ///
        /// # Scenario (Given)
        /// Random absolute paths over the alphabet {Users,u,Documents,Library,Caches,System,Volumes,
        /// Data,x,"",.,..,var,tmp,etc,private,db} (so doubled prefixes, `.`/`//` inside the prefix,
        /// `..`, and the `/private` aliases of AC-001-18 all occur);
        /// root `/Users/u/Library/Caches`; empty fake fs (lexical verdicts stay distinguishable:
        /// anything that passes lexical checks ends in `Io`).
        ///
        /// # Action (When)
        /// Compute `n = normalize(p)`, `normalize(n)`, and the verdict kinds of `p`, `n`, and
        /// `DATA + p`.
        ///
        /// # Expected (Then)
        /// `normalize(n) == n`; `kind(p) == kind(n)`; `kind(p) == kind(DATA + p)`.
        ///
        /// # Must never
        /// Panic; change a verdict through normalization.
        ///
        /// # Would catch
        /// Stripping the prefix only once (not idempotent on doubled prefixes), stripping before
        /// collapsing `.`/`//` (`/System/Volumes/./Data/x`), or any normalization that equates two
        /// paths with different verdicts.
        ///
        /// # Why this test (not redundant)
        /// The spec asks for a property here; examples above pin the expected verdicts, this pins
        /// the algebra over inputs no one would hand-write.
        #[test]
        fn ac_001_3_normalize_is_idempotent_and_never_flips_a_verdict(parts in components()) {
            let fs = FakeFs::builder().build();
            let g = guard();
            let p = PathBuf::from(format!("/{}", parts.join("/")));
            let n = normalize(&p);
            let prefixed = PathBuf::from(format!("{DATA}{}", p.display()));
            let verdict = |c: &Path| kind_of(&g.admit(&fs, Path::new(CACHES), c));

            let nn = normalize(&n);
            prop_assert_eq!(nn.as_os_str(), n.as_os_str(), "normalize must be idempotent for {:?}", p);
            prop_assert_eq!(verdict(&p), verdict(&n), "normalizing must not change the verdict of {:?}", p);
            prop_assert_eq!(verdict(&p), verdict(&prefixed), "firmlink prefix must not change the verdict of {:?}", p);
        }
    }

    /// # Design promise
    /// AC-001-4 / INV-07: syntactically unacceptable input is refused with the precise cause before
    /// any other judgement, with no filesystem access.
    ///
    /// # Scenario (Given)
    /// Empty fake fs. Rows: empty, relative, `./`-relative, relative root, `..` that would resolve
    /// inside the root, trailing `..`, and a `..` path that also reaches a denied dir.
    ///
    /// # Action (When)
    /// `admit` each row.
    ///
    /// # Expected (Then)
    /// Empty/relative (candidate or root) -> `NotAbsolute`; any `..` -> `Traversal`, including
    /// `.../Caches/../Caches/x` (resolves inside the root but is still refused) and
    /// `.../Caches/../../Documents/x` (`Traversal` wins over `DenyListed`); zero `Fs` calls.
    ///
    /// # Must never
    /// Resolve `..` lexically and accept; hit the filesystem for a syntax verdict.
    ///
    /// # Would catch
    /// Normalizing `..` away before checking, or checking the deny list first and reporting a less
    /// specific cause.
    ///
    /// # Why this test (not redundant)
    /// The only test of the syntax class; normalization of benign input is the next test.
    #[test]
    fn ac_001_4_relative_empty_and_dotdot_paths_are_rejected_before_anything_else() {
        // Arrange
        let fs = FakeFs::builder().build();
        let na = Err(DeniedKind::NotAbsolute);
        let tr = Err(DeniedKind::Traversal);
        let rows = [
            Row {
                name: "empty",
                root: CACHES,
                cand: "",
                want: na,
            },
            Row {
                name: "relative",
                root: CACHES,
                cand: "app/x",
                want: na,
            },
            Row {
                name: "dot-relative",
                root: CACHES,
                cand: "./app/x",
                want: na,
            },
            Row {
                name: "relative-root",
                root: "Library/Caches",
                cand: "/Users/u/Library/Caches/app/x",
                want: na,
            },
            Row {
                name: "dotdot-inside-root",
                root: CACHES,
                cand: "/Users/u/Library/Caches/../Caches/x",
                want: tr,
            },
            Row {
                name: "trailing-dotdot",
                root: CACHES,
                cand: "/Users/u/Library/Caches/app/..",
                want: tr,
            },
            Row {
                name: "dotdot-to-denied",
                root: CACHES,
                cand: "/Users/u/Library/Caches/../../Documents/x",
                want: tr,
            },
        ];

        // Act + Assert
        run_rows(&fs, &rows);
    }

    /// # Design promise
    /// AC-001-4: redundant `//`, `/./` and a trailing `/` are normalized, not rejected, and the
    /// admitted `SafePath` holds the clean spelling (root may be messy too).
    ///
    /// # Scenario (Given)
    /// Tree `/Users/u/Library/Caches/app/x`; three spellings of the same candidate/root pair.
    ///
    /// # Action (When)
    /// `admit` each spelling.
    ///
    /// # Expected (Then)
    /// All `Ok` with `path() == /Users/u/Library/Caches/app/x`.
    ///
    /// # Must never
    /// Reject benign spelling variants (it would push callers to hand-clean paths, bypassing us).
    ///
    /// # Would catch
    /// Using `Path::components` for checks but returning the raw string; treating `//` as an empty
    /// (hence traversal-like) component.
    ///
    /// # Why this test (not redundant)
    /// The success-side of the syntax class; `ac_001_3` only covers the firmlink spelling.
    #[test]
    fn ac_001_4_redundant_separators_and_dots_are_normalized_not_rejected() {
        // Arrange
        let fs = caches_tree().build();
        let rows = [
            (CACHES, "/Users/u/Library/Caches//app/./x"),
            (CACHES, "/Users/u/Library/Caches/app/x/"),
            (
                "/Users/u/Library//Caches/./",
                "/Users/u/Library/Caches/app/x",
            ),
        ];

        for (root, cand) in rows {
            // Act
            let got = guard().admit(&fs, Path::new(root), Path::new(cand));

            // Assert
            let safe =
                got.unwrap_or_else(|e| panic!("{cand:?} under {root:?} must be admitted: {e:?}"));
            // Compare as raw strings: `Path` equality is component-wise and would hide `//` and `/./`.
            assert_eq!(
                safe.path().as_os_str(),
                Path::new("/Users/u/Library/Caches/app/x").as_os_str(),
                "{cand:?}: SafePath must hold the normalized spelling"
            );
        }
    }

    /// # Design promise
    /// AC-001-4 / INV-07 (hostile names): unusual but legal names are handled without panic or
    /// injection and are admitted verbatim; non-UTF-8 bytes are judged by the same rules as UTF-8.
    ///
    /// # Scenario (Given)
    /// Existing files under the caches root named: with space, embedded newline, leading `-`, NFD
    /// `cafe\u{301}`, NFC `caf\u{e9}`, non-UTF-8 bytes `FF FE x`, 255 `a`s, and `...` (three dots,
    /// an ordinary name, not `..`). Plus a non-UTF-8 child of `~/Documents`.
    ///
    /// # Action (When)
    /// `admit` each.
    ///
    /// # Expected (Then)
    /// The 8 legal names are `Ok` and `path()` equals the input byte-for-byte (NFC and NFD stay
    /// distinct; no Unicode folding); the non-UTF-8 child of `Documents` is `DenyListed`.
    ///
    /// # Must never
    /// Panic on invalid UTF-8; fold NFC/NFD (which could alias two different files); treat `...`
    /// as traversal; let a denied directory's non-UTF-8 child slip through.
    ///
    /// # Would catch
    /// `to_str().unwrap()`, lossy conversion before comparison, or substring checks for `..`.
    ///
    /// # Why this test (not redundant)
    /// The only hostile-name coverage; classes of *semantic* rejection are in the other tests.
    #[test]
    fn ac_001_4_hostile_names_are_judged_by_the_same_rules_without_panic() {
        // Arrange
        let names: Vec<OsString> = vec![
            "with space".into(),
            "line\nbreak".into(),
            "-rf".into(),
            "cafe\u{301}".into(),
            "caf\u{e9}".into(),
            OsString::from_vec(vec![0xFF, 0xFE, b'x']),
            "a".repeat(255).into(),
            "...".into(),
        ];
        let mut b = FakeFs::builder().dir(CACHES);
        for n in &names {
            b = b.file(Path::new(CACHES).join(n));
        }
        let fs = b.build();
        let g = guard();

        for n in &names {
            // Act
            let cand = Path::new(CACHES).join(n);
            let got = g.admit(&fs, Path::new(CACHES), &cand);

            // Assert
            let safe =
                got.unwrap_or_else(|e| panic!("hostile but legal name {n:?} refused: {e:?}"));
            assert_eq!(
                safe.path().as_os_str(),
                cand.as_os_str(),
                "{n:?}: must be admitted verbatim"
            );
        }

        // Act + Assert: invalid UTF-8 under a denied directory is still denied.
        let denied = Path::new("/Users/u/Documents").join(OsString::from_vec(vec![0xFF, b'z']));
        let got = g.admit(&fs, Path::new(HOME), &denied);
        assert_eq!(
            kind_of(&got),
            Err(DeniedKind::DenyListed),
            "INV-06: non-UTF-8 child of Documents"
        );
    }

    /// # Design promise
    /// AC-001-5 / INV-07: containment is decided per path component; the root itself is never a
    /// deletion candidate.
    ///
    /// # Scenario (Given)
    /// Root `/Users/u/Library/Caches`; `Caches-old/x` and `app/x` exist. Rows: a descendant, a
    /// string-prefix lookalike, a second lookalike, the root itself, the root with a trailing
    /// slash, and an unrelated path.
    ///
    /// # Action (When)
    /// `admit` each.
    ///
    /// # Expected (Then)
    /// Descendant `Ok`; every other row `OutsideRoot` (lexical: zero `Fs` calls).
    ///
    /// # Must never
    /// Admit the root (a rule could then delete its own root); admit `Caches-old` via string prefix.
    ///
    /// # Would catch
    /// `candidate.to_str().starts_with(root)` and `>=` instead of `>` on component depth.
    ///
    /// # Why this test (not redundant)
    /// The only `admit` test of containment; `admit_root` is the next test.
    #[test]
    fn ac_001_5_containment_is_component_wise_and_the_root_is_not_a_candidate() {
        // Arrange
        let fs = caches_tree().file("/Users/u/Library/Caches-old/x").build();
        let oob = Err(DeniedKind::OutsideRoot);
        let rows = [
            Row {
                name: "descendant",
                root: CACHES,
                cand: "/Users/u/Library/Caches/app/x",
                want: Ok(()),
            },
            Row {
                name: "caches-old",
                root: CACHES,
                cand: "/Users/u/Library/Caches-old/x",
                want: oob,
            },
            Row {
                name: "cachesx",
                root: CACHES,
                cand: "/Users/u/Library/Cachesx",
                want: oob,
            },
            Row {
                name: "root-itself",
                root: CACHES,
                cand: CACHES,
                want: oob,
            },
            Row {
                name: "root-trailing-slash",
                root: CACHES,
                cand: "/Users/u/Library/Caches/",
                want: oob,
            },
            Row {
                name: "unrelated",
                root: CACHES,
                cand: "/tmp/x",
                want: oob,
            },
        ];

        // Act + Assert
        run_rows(&fs, &rows);
    }

    /// # Design promise
    /// AC-001-5 / spec 002 AC-002-11: `admit_root` is the only way to accept a root; it accepts a
    /// normal root (returned as-is) and applies the deny rules to the root itself.
    ///
    /// # Scenario (Given)
    /// Existing `/Users/u/Library/Caches`; rows: that root, `~/Documents`, `~/Library` (ancestor of
    /// Keychains), `$HOME`, `/`, and a relative root.
    ///
    /// # Action (When)
    /// `admit_root` each.
    ///
    /// # Expected (Then)
    /// Caches -> `Ok(path == root, not symlink)`; Documents -> `DenyListed`; Library, home, `/` ->
    /// `AncestorOfDenied`; relative -> `NotAbsolute`; every `Err` made zero `Fs` calls.
    ///
    /// # Must never
    /// Accept a root that is, or contains, a denied path.
    ///
    /// # Would catch
    /// An `admit_root` that only checks existence, letting a rule root swallow `~/Documents`.
    ///
    /// # Why this test (not redundant)
    /// Only test of the `admit_root` entry point's deny behavior (symlinked root: AC-001-6 test).
    #[test]
    fn ac_001_5_admit_root_accepts_a_clean_root_and_refuses_denied_or_ancestor_roots() {
        // Arrange
        let fs = FakeFs::builder()
            .dir(CACHES)
            .dir("/Users/u/Documents")
            .build();
        let g = guard();
        let rows = [
            ("clean", CACHES, Ok(())),
            (
                "documents",
                "/Users/u/Documents",
                Err(DeniedKind::DenyListed),
            ),
            (
                "library",
                "/Users/u/Library",
                Err(DeniedKind::AncestorOfDenied),
            ),
            ("home", HOME, Err(DeniedKind::AncestorOfDenied)),
            ("slash", "/", Err(DeniedKind::AncestorOfDenied)),
            ("relative", "Library/Caches", Err(DeniedKind::NotAbsolute)),
        ];

        for (name, root, want) in rows {
            // Act
            let before = fs.calls().len();
            let got = g.admit_root(&fs, Path::new(root));

            // Assert
            assert_eq!(
                kind_of(&got),
                want,
                "row `{name}`: wrong admit_root verdict"
            );
            if let Ok(safe) = &got {
                assert_eq!(
                    safe.path().as_os_str(),
                    Path::new(root).as_os_str(),
                    "row `{name}`: root returned unchanged"
                );
                assert!(
                    !safe.is_symlink(),
                    "row `{name}`: a real directory is not a symlink"
                );
                assert!(
                    safe.exists(),
                    "row `{name}`: an existing root has exists() == true"
                );
            } else {
                assert_eq!(
                    fs.calls().len(),
                    before,
                    "row `{name}`: refusal must be lexical"
                );
            }
        }
    }

    /// # Design promise
    /// AC-001-5 amendment: a rule root that does not exist is not unsafe (nothing can be touched
    /// there), so `admit_root` admits it, flagged `exists() == false`; spec 002 maps that to
    /// `status:"absent"`. Only an *absent* root gets this treatment.
    ///
    /// # Scenario (Given)
    /// `/Users/u` exists but `/Users/u/.npm/_cacache` (a typical absent rule root) does not. A second
    /// root `/Users/u/Library/Caches//Missing/` is absent and spelled messily.
    ///
    /// # Action (When)
    /// `admit_root` each.
    ///
    /// # Expected (Then)
    /// `Ok` with `exists() == false`, `is_symlink() == false`, and `path()` equal to the normalized
    /// spelling (`/Users/u/.npm/_cacache`, `/Users/u/Library/Caches/Missing`).
    ///
    /// # Must never
    /// Report `Io` for a plain `NotFound` (spec 002 could then not tell "absent" from "broken"), or
    /// report `exists() == true` for a root that is not there.
    ///
    /// # Would catch
    /// Treating every `lstat` error as `Io` (the pre-amendment behavior); defaulting `exists` to true.
    ///
    /// # Why this test (not redundant)
    /// Only coverage of the absent-root class; other `Fs` errors are in the AC-001-10 test and denied
    /// absent roots in the next test.
    #[test]
    fn ac_001_5_admit_root_admits_a_missing_root_flagged_not_existing() {
        // Arrange
        let fs = FakeFs::builder().dir(HOME).build();
        let rows = [
            ("npm", "/Users/u/.npm/_cacache", "/Users/u/.npm/_cacache"),
            (
                "messy",
                "/Users/u/Library/Caches//Missing/",
                "/Users/u/Library/Caches/Missing",
            ),
        ];

        for (name, root, want_path) in rows {
            // Act
            let got = guard().admit_root(&fs, Path::new(root));

            // Assert
            let safe =
                got.unwrap_or_else(|e| panic!("row `{name}`: absent root must be admitted: {e:?}"));
            assert!(
                !safe.exists(),
                "row `{name}`: exists() must be false for a missing root"
            );
            assert!(
                !safe.is_symlink(),
                "row `{name}`: a missing root is not a symlink"
            );
            assert_eq!(
                safe.path().as_os_str(),
                Path::new(want_path).as_os_str(),
                "row `{name}`: path must be the normalized spelling"
            );
        }
    }

    /// # Design promise
    /// AC-001-5 amendment / INV-06: absence never launders a root. A denied or ancestor-of-denied root
    /// that happens not to exist is still refused, and the verdict is lexical (no `Fs` access).
    ///
    /// # Scenario (Given)
    /// An EMPTY fake filesystem, so every root below is absent. Rows: `~/Documents`,
    /// `~/.ssh` (denied), `/Users/u/Library` (ancestor of Keychains), `$HOME`, and a relative root.
    ///
    /// # Action (When)
    /// `admit_root` each.
    ///
    /// # Expected (Then)
    /// `DenyListed`, `DenyListed`, `AncestorOfDenied`, `AncestorOfDenied`, `NotAbsolute`; zero `Fs`
    /// calls.
    ///
    /// # Must never
    /// Return `Ok(exists=false)` for a denied root (a later `mkdir` by the user or another tool would
    /// then be scanned/acted on as a rule root).
    ///
    /// # Would catch
    /// `if lstat == NotFound { return Ok(absent) }` placed before the lexical checks.
    ///
    /// # Why this test (not redundant)
    /// The existing `admit_root` table uses roots that exist; only absent denied roots can kill an
    /// early-return-on-absence mutant.
    #[test]
    fn ac_001_5_admit_root_refuses_a_denied_root_even_when_it_does_not_exist() {
        // Arrange
        let fs = FakeFs::builder().build();
        let rows = [
            ("documents", "/Users/u/Documents", DeniedKind::DenyListed),
            ("ssh", "/Users/u/.ssh", DeniedKind::DenyListed),
            ("library", "/Users/u/Library", DeniedKind::AncestorOfDenied),
            ("home", HOME, DeniedKind::AncestorOfDenied),
            ("relative", "Library/Caches", DeniedKind::NotAbsolute),
        ];

        for (name, root, want) in rows {
            // Act
            let got = guard().admit_root(&fs, Path::new(root));

            // Assert
            assert_eq!(
                kind_of(&got),
                Err(want),
                "row `{name}`: an absent denied root must still be refused"
            );
        }
        assert!(
            fs.calls().is_empty(),
            "these verdicts are lexical: no Fs access allowed"
        );
    }

    /// # Design promise
    /// AC-001-17 / INV-06: default APFS volumes are case- and normalization-insensitive, so every
    /// spelling of a denied directory (case variants, NFC/NFD) *is* that directory. Deny-list and
    /// ancestor matching must therefore compare folded components (Unicode case-fold + NFC), erring
    /// on the side of over-blocking; containment stays exact and case-sensitive, so folding can only
    /// ever refuse more, never admit something.
    ///
    /// # Scenario (Given)
    /// Group 1, guard for home `/Users/u`: `documents`, `/users/u/Documents`, `/USERS/U/DOCUMENTS/x`,
    /// `Library/KEYCHAINS`, `/SYSTEM/Library/x`, `/PRIVATE/VAR/DB/x` (case variants of fixed and
    /// home-relative entries); ancestors `/USERS/U`, `/users`, `/USERS/U/library` (case-variant
    /// ancestors). Group 2, guard for the NFC home `/Users/jos\u{e9}` with the NFC extra entry
    /// `/opt/Caf\u{e9}`: NFD home (`jose\u{301}`) with `Documents`, upper-case `JOS\u{c9}` with
    /// `documents`, NFD and upper-case spellings of the extra entry, and the NFD home as an ancestor.
    /// Group 3 (must still be admitted): `Documents-old/x`, `Documentsx`, and the case variant
    /// `documents-old/x` (all really exist in the tree, as distinct entries). Group 4 (exact
    /// containment): root `/Users/u/Library/Caches` with candidates `/Users/u/library/caches/app/x`
    /// and `/Users/u/Library/caches/x`.
    ///
    /// # Action (When)
    /// `admit` each row.
    ///
    /// # Expected (Then)
    /// Group 1 and 2: `DenyListed` for entries and descendants, `AncestorOfDenied` for the ancestor
    /// rows. Group 3: `Ok`. Group 4: `OutsideRoot` (a case-different spelling is not "inside" the
    /// root, even though APFS would alias it). Every lexical refusal made zero `Fs` calls.
    ///
    /// # Must never
    /// Let `/Users/u/documents` (the same directory as `Documents` on APFS) through; admit a
    /// path because its folded form happens to sit under the root; over-block `Documents-old`.
    ///
    /// # Would catch
    /// Byte-exact component comparison (the bypass); folding applied to containment as well (it
    /// would admit or mis-classify case-different candidates); folding implemented as a string
    /// prefix/`contains` match (would deny `Documentsx`).
    ///
    /// # Why this test (not redundant)
    /// The only coverage of aliasing. It does not conflict with the hostile-name test above: that one
    /// pins NFC and NFD as *distinct names for admission* using a non-denied name (`caf\u{e9}`),
    /// which stays true: folding only widens what the *deny list* matches, never merges candidates.
    #[test]
    #[allow(clippy::too_many_lines, reason = "table rows")]
    fn ac_001_17_deny_matching_survives_apfs_case_and_normalization_aliasing() {
        // Arrange
        let dl = Err(DeniedKind::DenyListed);
        let anc = Err(DeniedKind::AncestorOfDenied);
        let oob = Err(DeniedKind::OutsideRoot);
        let fs = FakeFs::builder()
            .file("/Users/u/Documents-old/x")
            .file("/Users/u/Documentsx")
            .file("/Users/u/documents-old/x")
            .build();
        let plain = [
            Row {
                name: "lower-documents",
                root: HOME,
                cand: "/Users/u/documents",
                want: dl,
            },
            Row {
                name: "lower-users",
                root: HOME,
                cand: "/users/u/Documents",
                want: dl,
            },
            Row {
                name: "upper-descendant",
                root: HOME,
                cand: "/USERS/U/DOCUMENTS/x",
                want: dl,
            },
            Row {
                name: "keychains",
                root: HOME,
                cand: "/Users/u/Library/KEYCHAINS",
                want: dl,
            },
            Row {
                name: "upper-system",
                root: "/",
                cand: "/SYSTEM/Library/x",
                want: dl,
            },
            Row {
                name: "upper-private-db",
                root: "/",
                cand: "/PRIVATE/VAR/DB/x",
                want: dl,
            },
            Row {
                name: "ancestor-upper-home",
                root: CACHES,
                cand: "/USERS/U",
                want: anc,
            },
            Row {
                name: "ancestor-lower-users",
                root: CACHES,
                cand: "/users",
                want: anc,
            },
            Row {
                name: "ancestor-lower-library",
                root: CACHES,
                cand: "/USERS/U/library",
                want: anc,
            },
            Row {
                name: "lookalike-old",
                root: HOME,
                cand: "/Users/u/Documents-old/x",
                want: Ok(()),
            },
            Row {
                name: "lookalike-x",
                root: HOME,
                cand: "/Users/u/Documentsx",
                want: Ok(()),
            },
            Row {
                name: "lookalike-lower-old",
                root: HOME,
                cand: "/Users/u/documents-old/x",
                want: Ok(()),
            },
            Row {
                name: "case-different-root",
                root: CACHES,
                cand: "/Users/u/library/caches/app/x",
                want: oob,
            },
            Row {
                name: "case-different-leaf",
                root: CACHES,
                cand: "/Users/u/Library/caches/x",
                want: oob,
            },
        ];
        let unicode_guard = SafetyGuard::new(&HomeDir::new("/Users/jos\u{e9}"))
            .with_extra_denied([PathBuf::from("/opt/Caf\u{e9}")]);
        let unicode = [
            Row {
                name: "nfd-home",
                root: "/",
                cand: "/Users/jose\u{301}/Documents/x",
                want: dl,
            },
            Row {
                name: "upper-home-lower-dir",
                root: "/",
                cand: "/Users/JOS\u{c9}/documents",
                want: dl,
            },
            Row {
                name: "nfd-extra",
                root: "/",
                cand: "/opt/Cafe\u{301}/x",
                want: dl,
            },
            Row {
                name: "upper-extra",
                root: "/",
                cand: "/OPT/CAF\u{c9}",
                want: dl,
            },
            Row {
                name: "nfd-home-ancestor",
                root: "/",
                cand: "/Users/jose\u{301}",
                want: anc,
            },
        ];

        // Act + Assert
        run_rows(&fs, &plain);
        run_rows_with(&unicode_guard, &fs, &unicode);
    }

    /// # Design promise
    /// AC-001-18 / INV-06: `/var`, `/etc` and `/tmp` are symlinks to `/private/{var,etc,tmp}`, so
    /// `normalize` rewrites a *leading* such component to its `/private` form (after the firmlink
    /// prefix is stripped) and the deny list then sees `/var/db/x` as `/private/var/db/x`. Nothing
    /// else changes, and the function stays idempotent.
    ///
    /// # Scenario (Given)
    /// Rewritten: `/var/db/x`, `/etc/hosts`, `/tmp/x`, bare `/var` and `/tmp`, and
    /// `/System/Volumes/Data/var/db/x` (both rules compose). Unchanged: `/private/var/db/x`,
    /// `/private/tmp/x`, `/private`, look-alikes `/variable/x`, `/tmpx`, `/etcetera`, and non-leading
    /// `/Users/u/var`, `/Users/u/tmp/x`, `/usr/var`. Guard rows: `/var/db/x` under root `/` (must be
    /// denied), and `/tmp/x` under root `/tmp` with `/private/tmp/x` present (must be admitted,
    /// reported as `/private/tmp/x`).
    ///
    /// # Action (When)
    /// `normalize` each path (and `normalize` its result again); then `admit` the guard rows.
    ///
    /// # Expected (Then)
    /// Output equals the expected spelling (compared as raw strings) and a second `normalize` changes
    /// nothing; `/var/db/x` -> `Err(DenyListed)` with zero `Fs` calls; the `/tmp` row is `Ok` with
    /// `path() == /private/tmp/x`.
    ///
    /// # Must never
    /// Rewrite a non-leading or look-alike component (it would alias unrelated paths and break
    /// containment), or judge `/var/db/x` differently from `/private/var/db/x` (alias bypass of
    /// `~/../private/var/db`).
    ///
    /// # Would catch
    /// No alias rule (bypass through `/var/db`), a `starts_with("/var")` string match (rewrites
    /// `/variable`), rewriting every `var` component, or applying the alias before stripping the
    /// firmlink prefix.
    ///
    /// # Why this test (not redundant)
    /// Pins the exact rewrite table, which the proptest (alphabet now includes the alias words) only
    /// checks for idempotence and verdict stability, not for the expected output.
    #[test]
    fn ac_001_18_private_aliases_are_rewritten_only_when_leading() {
        // Arrange
        let rows = [
            ("var-db", "/var/db/x", "/private/var/db/x"),
            ("etc", "/etc/hosts", "/private/etc/hosts"),
            ("tmp", "/tmp/x", "/private/tmp/x"),
            ("bare-var", "/var", "/private/var"),
            ("bare-tmp", "/tmp", "/private/tmp"),
            (
                "firmlink-then-alias",
                "/System/Volumes/Data/var/db/x",
                "/private/var/db/x",
            ),
            ("already-private", "/private/var/db/x", "/private/var/db/x"),
            ("already-private-tmp", "/private/tmp/x", "/private/tmp/x"),
            ("private-alone", "/private", "/private"),
            ("variable", "/variable/x", "/variable/x"),
            ("tmpx", "/tmpx", "/tmpx"),
            ("etcetera", "/etcetera", "/etcetera"),
            ("home-var", "/Users/u/var", "/Users/u/var"),
            ("home-tmp", "/Users/u/tmp/x", "/Users/u/tmp/x"),
            ("usr-var", "/usr/var", "/usr/var"),
        ];

        for (name, input, want) in rows {
            // Act
            let once = normalize(Path::new(input));
            let twice = normalize(&once);

            // Assert
            assert_eq!(
                once.as_os_str(),
                Path::new(want).as_os_str(),
                "row `{name}`: wrong normalization of {input}"
            );
            assert_eq!(
                twice.as_os_str(),
                once.as_os_str(),
                "row `{name}`: normalize must be idempotent"
            );
        }

        // Act + Assert: the guard sees through the alias.
        let empty = FakeFs::builder().build();
        let denied = guard().admit(&empty, Path::new("/"), Path::new("/var/db/x"));
        assert_eq!(
            kind_of(&denied),
            Err(DeniedKind::DenyListed),
            "INV-06: /var/db/x is /private/var/db/x"
        );
        assert!(
            empty.calls().is_empty(),
            "the alias verdict is lexical: no Fs access"
        );
        let fs = FakeFs::builder().file("/private/tmp/x").build();
        let admitted = guard()
            .admit(&fs, Path::new("/tmp"), Path::new("/tmp/x"))
            .expect("an alias-spelled candidate under an alias-spelled root is admitted");
        assert_eq!(
            admitted.path().as_os_str(),
            Path::new("/private/tmp/x").as_os_str(),
            "the admitted path is reported in its /private spelling"
        );
    }

    /// Tree for the symlink tests: root `/Users/u/Library/Caches` with a regular `app/x`, a live link
    /// to `~/Documents`, a dangling link, a self-loop, a 2-cycle, and a link to a dir inside the root.
    fn link_tree() -> FakeFs {
        FakeFs::builder()
            .file(format!("{CACHES}/app/x"))
            .file("/Users/u/Documents/secret")
            .symlink(format!("{CACHES}/link"), "/Users/u/Documents")
            .symlink(format!("{CACHES}/dangling"), "/nowhere")
            .symlink(format!("{CACHES}/loop"), format!("{CACHES}/loop"))
            .symlink(format!("{CACHES}/ping"), format!("{CACHES}/pong"))
            .symlink(format!("{CACHES}/pong"), format!("{CACHES}/ping"))
            .symlink(format!("{CACHES}/inside"), format!("{CACHES}/app"))
            .build()
    }

    /// # Design promise
    /// AC-001-6 / INV-07: a symlink as the *final* component is admitted as a link (it may be
    /// removed as a link) and is never traversed; loops and dangling links terminate.
    ///
    /// # Scenario (Given)
    /// `link_tree()`: links to `~/Documents` (live), to nowhere (dangling), to itself (loop), a
    /// 2-cycle, and to a dir inside the root; plus a regular file.
    ///
    /// # Action (When)
    /// `admit(root, root/<name>)` for each link and for the regular file.
    ///
    /// # Expected (Then)
    /// Each link: `Ok` with `is_symlink() == true`; the regular file: `Ok`, `is_symlink() == false`.
    /// No `lstat` call was made on any path strictly below a link.
    ///
    /// # Must never
    /// Follow a link (stat its target or look inside it); hang on a loop; refuse a dangling link.
    ///
    /// # Would catch
    /// Using `metadata`/`canonicalize` (follows links, ELOOP on loops, ENOENT on dangling) instead
    /// of `lstat`.
    ///
    /// # Why this test (not redundant)
    /// The only final-component symlink coverage; parent-component links are the next test.
    #[test]
    fn ac_001_6_final_symlink_is_admitted_as_a_link_and_never_traversed() {
        // Arrange
        let fs = link_tree();
        let links = ["link", "dangling", "loop", "ping", "inside"];

        for name in links {
            // Act
            let cand = format!("{CACHES}/{name}");
            let got = guard().admit(&fs, Path::new(CACHES), Path::new(&cand));

            // Assert
            let safe =
                got.unwrap_or_else(|e| panic!("link `{name}` must be admitted as a link: {e:?}"));
            assert!(
                safe.is_symlink(),
                "link `{name}` must be flagged is_symlink"
            );
        }
        let regular = guard()
            .admit(
                &fs,
                Path::new(CACHES),
                Path::new(&format!("{CACHES}/app/x")),
            )
            .expect("regular file is admitted");
        assert!(
            !regular.is_symlink(),
            "a regular file must not be flagged as a symlink"
        );
        for call in fs.calls() {
            for name in links {
                let link = PathBuf::from(format!("{CACHES}/{name}"));
                assert!(
                    !(call.starts_with(&link) && call != link),
                    "INV-07: guard looked below symlink {link:?} via {call:?}"
                );
            }
        }
    }

    /// # Design promise
    /// AC-001-6 / INV-07: a symlink among the *parent* components between root and candidate is a
    /// `SymlinkEscape` - conservatively, whatever its target - and loops terminate with that error.
    ///
    /// # Scenario (Given)
    /// `link_tree()`. Rows: parent link to `~/Documents` (the spec's `root/link/secret`), parent link
    /// to a dir *inside* the root (`inside/x`), self-looping parent, 2-cycle parent.
    ///
    /// # Action (When)
    /// `admit(root, root/<link>/<leaf>)`.
    ///
    /// # Expected (Then)
    /// All `Err(SymlinkEscape)`, and the call returns (no hang). The inside-root row is pinned to
    /// `SymlinkEscape` as well: the path *names* `inside/x` but would act on `app/x`, so the plan
    /// and the action would differ (conservative reading of AC-001-6; flagged for ratification).
    ///
    /// # Must never
    /// Admit a path whose real location differs from its spelled location; hang on a cycle.
    ///
    /// # Would catch
    /// Checking only the final component, or comparing the *resolved* path to the root (which
    /// admits the inside-root case and loops forever on cycles).
    ///
    /// # Why this test (not redundant)
    /// The only parent-link coverage (the escape the invariant exists for).
    #[test]
    fn ac_001_6_symlink_in_a_parent_component_is_a_symlink_escape() {
        // Arrange
        let fs = link_tree();
        let esc = Err(DeniedKind::SymlinkEscape);
        let rows = [
            Row {
                name: "to-documents",
                root: CACHES,
                cand: "/Users/u/Library/Caches/link/secret",
                want: esc,
            },
            Row {
                name: "to-inside-root",
                root: CACHES,
                cand: "/Users/u/Library/Caches/inside/x",
                want: esc,
            },
            Row {
                name: "self-loop",
                root: CACHES,
                cand: "/Users/u/Library/Caches/loop/x",
                want: esc,
            },
            Row {
                name: "two-cycle",
                root: CACHES,
                cand: "/Users/u/Library/Caches/ping/x",
                want: esc,
            },
        ];

        // Act + Assert
        run_rows(&fs, &rows);
    }

    /// # Design promise
    /// AC-001-6 / INV-07: a symlinked *root* is refused by both entry points.
    ///
    /// # Scenario (Given)
    /// `/Users/u/linked-root` is a symlink to `/Users/u/Library/Caches`, whose `app/x` exists.
    ///
    /// # Action (When)
    /// `admit(linked-root, linked-root/app/x)` and `admit_root(linked-root)`.
    ///
    /// # Expected (Then)
    /// Both `Err(SymlinkEscape)`.
    ///
    /// # Must never
    /// Treat a link as a trusted root (the whole walk would escape the rule's intended location).
    ///
    /// # Would catch
    /// Validating only descendants, or `canonicalize`-ing the root before checking.
    ///
    /// # Why this test (not redundant)
    /// Only root-is-a-link coverage; other symlink tests have a real root.
    #[test]
    fn ac_001_6_symlinked_root_is_a_symlink_escape_for_both_entry_points() {
        // Arrange
        let fs = caches_tree()
            .symlink("/Users/u/linked-root", CACHES)
            .build();
        let g = guard();
        let root = Path::new("/Users/u/linked-root");

        // Act
        let via_admit = g.admit(&fs, root, Path::new("/Users/u/linked-root/app/x"));
        let via_root = g.admit_root(&fs, root);

        // Assert
        assert_eq!(
            kind_of(&via_admit),
            Err(DeniedKind::SymlinkEscape),
            "admit under a symlinked root"
        );
        assert_eq!(
            kind_of(&via_root),
            Err(DeniedKind::SymlinkEscape),
            "admit_root of a symlinked root"
        );
    }

    /// # Design promise
    /// AC-001-7 / INV-08: a candidate (or its parent) on a different device than the root is
    /// `CrossDevice`; the comparison is against the *root's* device, not a constant.
    ///
    /// # Scenario (Given)
    /// Fs A (root dev 1): `app/x` (dev 1); `mnt` mount (dev 2) with `mnt/x`; `mixed` (dev 2) with a
    /// child `mixed/y` explicitly on dev 1 (parent differs, child equals root). Fs B: the root itself
    /// on dev 3 with ordinary children (inherit 3).
    ///
    /// # Action (When)
    /// `admit` `app/x`, `mnt`, `mnt/x`, `mixed/y` on A and `app/x` on B.
    ///
    /// # Expected (Then)
    /// A: `Ok`, `CrossDevice`, `CrossDevice`, `CrossDevice`; B: `Ok`.
    ///
    /// # Must never
    /// Descend/accept across a mount point; hard-code device 1.
    ///
    /// # Would catch
    /// Comparing only the candidate's device, or comparing against `DEFAULT_DEV`.
    ///
    /// # Why this test (not redundant)
    /// The only device-boundary coverage.
    #[test]
    fn ac_001_7_candidate_or_parent_on_another_device_is_cross_device() {
        // Arrange
        let fs_a = caches_tree()
            .file(format!("{CACHES}/mnt/x"))
            .file(format!("{CACHES}/mixed/y"))
            .dev(format!("{CACHES}/mnt"), 2)
            .dev(format!("{CACHES}/mixed"), 2)
            .dev(format!("{CACHES}/mixed/y"), 1)
            .build();
        let fs_b = caches_tree().dev(CACHES, 3).build();
        let cd = Err(DeniedKind::CrossDevice);
        let rows_a = [
            Row {
                name: "same-device",
                root: CACHES,
                cand: "/Users/u/Library/Caches/app/x",
                want: Ok(()),
            },
            Row {
                name: "mount-point-itself",
                root: CACHES,
                cand: "/Users/u/Library/Caches/mnt",
                want: cd,
            },
            Row {
                name: "below-mount",
                root: CACHES,
                cand: "/Users/u/Library/Caches/mnt/x",
                want: cd,
            },
            Row {
                name: "parent-differs",
                root: CACHES,
                cand: "/Users/u/Library/Caches/mixed/y",
                want: cd,
            },
        ];
        let rows_b = [Row {
            name: "root-on-dev-3",
            root: CACHES,
            cand: "/Users/u/Library/Caches/app/x",
            want: Ok(()),
        }];

        // Act + Assert
        run_rows(&fs_a, &rows_a);
        run_rows(&fs_b, &rows_b);
    }

    /// # Design promise
    /// AC-001-8 / INV-06: user-supplied deny entries are *added*; built-in entries stay denied, even
    /// when the extra list repeats them.
    ///
    /// # Scenario (Given)
    /// `with_extra_denied(["/Users/u/Work/secret", "/Users/u/Documents"])` (the second duplicates a
    /// built-in). `/Users/u/Work/other/x` exists.
    ///
    /// # Action (When)
    /// `admit` under root `/Users/u/Work`/`/Users/u`: the extra entry, its descendant, its parent,
    /// a built-in entry's child, `~/.ssh/id_rsa`, and the unrelated `Work/other/x`.
    ///
    /// # Expected (Then)
    /// `DenyListed`, `DenyListed`, `AncestorOfDenied` (the parent), `DenyListed`, `DenyListed`, `Ok`.
    ///
    /// # Must never
    /// Let configuration shrink the built-in list (the API has no remove/override; reviewed
    /// structurally, see worksheet).
    ///
    /// # Would catch
    /// `with_extra_denied` replacing the list instead of extending it.
    ///
    /// # Why this test (not redundant)
    /// Only coverage of the config-extension API.
    #[test]
    fn ac_001_8_extra_denied_paths_add_to_the_builtin_list_and_never_replace_it() {
        // Arrange
        let fs = FakeFs::builder().file("/Users/u/Work/other/x").build();
        let g = guard().with_extra_denied([
            PathBuf::from("/Users/u/Work/secret"),
            PathBuf::from("/Users/u/Documents"),
        ]);
        let rows = [
            (
                "extra-itself",
                "/Users/u/Work",
                "/Users/u/Work/secret",
                Err(DeniedKind::DenyListed),
            ),
            (
                "extra-child",
                "/Users/u/Work",
                "/Users/u/Work/secret/a",
                Err(DeniedKind::DenyListed),
            ),
            (
                "extra-parent",
                "/Users/u",
                "/Users/u/Work",
                Err(DeniedKind::AncestorOfDenied),
            ),
            (
                "builtin-documents",
                HOME,
                "/Users/u/Documents/a",
                Err(DeniedKind::DenyListed),
            ),
            (
                "builtin-ssh",
                HOME,
                "/Users/u/.ssh/id_rsa",
                Err(DeniedKind::DenyListed),
            ),
            (
                "unrelated",
                "/Users/u/Work",
                "/Users/u/Work/other/x",
                Ok(()),
            ),
        ];

        for (name, root, cand, want) in rows {
            // Act
            let got = g.admit(&fs, Path::new(root), Path::new(cand));

            // Assert
            assert_eq!(
                kind_of(&got),
                want,
                "row `{name}`: wrong verdict for {cand}"
            );
        }
    }

    /// # Design promise
    /// AC-001-9 / INV-07 (TOCTOU contract): every `admit` re-resolves through `Fs`; a verdict is
    /// never cached, in either direction.
    ///
    /// # Scenario (Given)
    /// `Caches/dir/x` is a regular file under a real directory; the guard instance is reused.
    ///
    /// # Action (When)
    /// First `admit(root, dir/x)`; then swap `dir` for a symlink to `~/Documents` and admit again;
    /// then swap `dir` for an empty directory and admit again.
    ///
    /// # Expected (Then)
    /// Step 1 `Ok`; step 2 `Err(SymlinkEscape)`; step 3 `Err(Io)` (the file is gone: proves the stale
    /// `SymlinkEscape` was not replayed). The number of recorded `lstat` calls strictly grows on
    /// every admit.
    ///
    /// # Must never
    /// Replay an earlier verdict; skip resolution on a repeated input.
    ///
    /// # Would catch
    /// A memoizing guard (`HashMap<PathBuf, Verdict>`) - the attack the executor re-validation relies
    /// on not existing.
    ///
    /// # Why this test (not redundant)
    /// The only multi-call (state-change) test; single-call tests cannot see caching.
    #[test]
    fn ac_001_9_toctou_every_admit_re_resolves_through_the_fs() {
        // Arrange
        let fs = FakeFs::builder()
            .file(format!("{CACHES}/dir/x"))
            .file("/Users/u/Documents/secret")
            .build();
        let g = guard();
        let cand = format!("{CACHES}/dir/x");
        let admit = || kind_of(&g.admit(&fs, Path::new(CACHES), Path::new(&cand)));

        // Act + Assert
        let first = admit();
        let calls_1 = fs.calls().len();
        assert_eq!(
            first,
            Ok(()),
            "step 1: a plain file under a real dir is admitted"
        );

        fs.replace_with_symlink(format!("{CACHES}/dir"), "/Users/u/Documents");
        let second = admit();
        let calls_2 = fs.calls().len();
        assert_eq!(
            second,
            Err(DeniedKind::SymlinkEscape),
            "step 2: swapped-in symlink must be caught"
        );

        fs.replace_with_dir(format!("{CACHES}/dir"));
        let third = admit();
        let calls_3 = fs.calls().len();
        assert_eq!(
            third,
            Err(DeniedKind::Io),
            "step 3: stale verdict replayed instead of re-resolving"
        );

        assert!(
            calls_1 > 0 && calls_2 > calls_1 && calls_3 > calls_2,
            "every admit must hit Fs again"
        );
    }

    /// # Design promise
    /// AC-001-10 / INV-13: any `Fs` error while resolving - on the candidate, a parent, the root,
    /// including ENAMETOOLONG, or simply a missing *candidate* - yields `Err(Io)`; never `Ok`. Same for
    /// `admit_root`, except that a plainly missing root is the absent-root class (admitted with
    /// `exists() == false`, see AC-001-5 amendment); any other error is still `Io`.
    ///
    /// # Scenario (Given)
    /// Rows with injected errors: EACCES on the candidate, EIO on the root, EACCES on a parent,
    /// ENAMETOOLONG (63) on the candidate, a missing candidate, a missing parent; for `admit_root`:
    /// EACCES on the root, and a missing root whose *parent* fails with EACCES (an error that is not
    /// plain `NotFound`).
    ///
    /// # Action (When)
    /// `admit` / `admit_root` for each.
    ///
    /// # Expected (Then)
    /// Every result is `Err(Io)`.
    ///
    /// # Must never
    /// Return `Ok` (or panic) when the filesystem could not be consulted - fail closed.
    ///
    /// # Would catch
    /// `unwrap_or(default metadata)`, `if let Ok(md) = lstat(..)` skipping the check on error, or
    /// mapping `NotFound` to "fine".
    ///
    /// # Why this test (not redundant)
    /// The only dependency-failure coverage of the guard.
    #[test]
    fn ac_001_10_any_fs_error_fails_closed_as_io() {
        // Arrange
        let app_x = format!("{CACHES}/app/x");
        let cases: Vec<(&str, FakeFs, String)> = vec![
            (
                "candidate-eacces",
                caches_tree().error_at(&app_x, 13).build(),
                app_x.clone(),
            ),
            (
                "root-eio",
                caches_tree().error_at(CACHES, 5).build(),
                app_x.clone(),
            ),
            (
                "parent-eacces",
                caches_tree().error_at(format!("{CACHES}/app"), 13).build(),
                app_x.clone(),
            ),
            (
                "candidate-enametoolong",
                caches_tree().error_at(&app_x, 63).build(),
                app_x.clone(),
            ),
            (
                "candidate-missing",
                caches_tree().build(),
                format!("{CACHES}/app/missing"),
            ),
            (
                "parent-missing",
                caches_tree().build(),
                format!("{CACHES}/nodir/x"),
            ),
        ];
        let g = guard();

        for (name, fs, cand) in &cases {
            // Act
            let got = g.admit(fs, Path::new(CACHES), Path::new(cand));

            // Assert
            assert_eq!(
                kind_of(&got),
                Err(DeniedKind::Io),
                "case `{name}`: must fail closed with Io"
            );
        }
        let fs = caches_tree().error_at(CACHES, 13).build();
        let root = g.admit_root(&fs, Path::new(CACHES));
        assert_eq!(
            kind_of(&root),
            Err(DeniedKind::Io),
            "admit_root must fail closed with Io too"
        );
        // A missing root whose lookup fails for a reason other than NotFound is not "absent".
        let fs = FakeFs::builder()
            .dir(HOME)
            .error_at("/Users/u/Library", 13)
            .build();
        let missing_root = g.admit_root(&fs, Path::new(CACHES));
        assert_eq!(
            kind_of(&missing_root),
            Err(DeniedKind::Io),
            "EACCES on the parent of a missing root must be Io, not an absent root"
        );
    }
}
