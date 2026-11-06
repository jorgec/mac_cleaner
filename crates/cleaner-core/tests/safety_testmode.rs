//! INV-15 test-mode decision (spec 001 AC-001-15), core half. The CLI wiring (env parsing, exit
//! code 3, nothing created) is tested in `cleaner-cli/tests/test_mode.rs`.
//!
//! # Worksheet 1 - `testmode::is_enabled` (fail-closed env interpretation, AC-001-15 amendment)
//! ```text
//! Function:        cleaner_core::testmode::is_enabled(Option<&OsStr>) -> bool
//! Contract:        pure. OFF only for None, "" or exactly "0"; every other value is ON (a typo must
//!                  not silently disable the protection). (AC-001-15, INV-15)
//! Equivalence classes: unset | empty | "0" | "1" | other truthy words | near-misses of "0"
//!                  | non-UTF-8
//! Boundaries:      "0" vs "00" / " 0"; "" vs " "
//! Must-never:      OFF for an unrecognized value
//! Selected tests:  ac_001_15_only_unset_empty_or_zero_leave_the_guard_off (one table)
//! Deliberately not tested: reading the environment (CLI test).
//! ```
//!
//! # Worksheet 2 - `testmode::check`
//! ```text
//! Function:        cleaner_core::testmode::check(test_mode, home, temp_dir)
//! Contract:        pure. test_mode=false -> Ok whatever home is. test_mode=true -> Ok only if home
//!                  is absolute, contains no `.`/`..`, and is STRICTLY below temp_dir
//!                  (component-wise). Otherwise Err(TestModeViolation) whose Display names `home`.
//!                  (AC-001-15, INV-15)
//! Equivalence classes: mode off | inside (shallow, deep) | outside | string-prefix lookalike
//!                  | equals temp | ancestor of temp | `..` escape | relative
//! Boundaries:      temp_dir itself vs one below; `T` vs `T-evil`
//! Must-never:      Ok for a home that could be the real home while test mode is on
//! Selected tests:  ac_001_15_test_mode_refuses_homes_outside_the_system_temp_dir (one table)
//! Deliberately not tested: canonicalization / env reading (composition root; CLI test).
//! ```

mod safety {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;

    use cleaner_core::testmode::{check, is_enabled};

    /// # Design promise
    /// AC-001-15 amendment (fail-closed) / INV-15: the test-mode guard is OFF only when
    /// `CLEANER_TEST_MODE` is unset, empty, or exactly `0`. Every other value turns it ON, so a typo
    /// such as `ture` can never silently disable the protection.
    ///
    /// # Scenario (Given)
    /// Raw values: unset, `""`, `"0"` (expected OFF); `"1"`, `"true"`, `"yes"`, `"foo"`, `"00"`,
    /// `" 0"`, `" "`, and a non-UTF-8 value `FF FE` (expected ON).
    ///
    /// # Action (When)
    /// `is_enabled(value)` for each.
    ///
    /// # Expected (Then)
    /// `false` for the first three rows, `true` for all the others.
    ///
    /// # Must never
    /// Return `false` for a value that is not unset/empty/`0` (fail-open).
    ///
    /// # Would catch
    /// `value == Some("1")` (the pre-amendment reading), `parse::<bool>()`, trimming whitespace
    /// before comparing with `0`, or treating non-UTF-8 as unset.
    ///
    /// # Why this test (not redundant)
    /// The only coverage of the env-value policy; `check` below covers the home/temp decision and the
    /// CLI test covers that the binary actually uses this function.
    #[test]
    fn ac_001_15_only_unset_empty_or_zero_leave_the_guard_off() {
        // Arrange
        let non_utf8 = OsString::from_vec(vec![0xFF, 0xFE]);
        let rows: [(&str, Option<&OsStr>, bool); 11] = [
            ("unset", None, false),
            ("empty", Some(OsStr::new("")), false),
            ("zero", Some(OsStr::new("0")), false),
            ("one", Some(OsStr::new("1")), true),
            ("true", Some(OsStr::new("true")), true),
            ("yes", Some(OsStr::new("yes")), true),
            ("foo", Some(OsStr::new("foo")), true),
            ("double-zero", Some(OsStr::new("00")), true),
            ("space-zero", Some(OsStr::new(" 0")), true),
            ("space", Some(OsStr::new(" ")), true),
            ("non-utf8", Some(non_utf8.as_os_str()), true),
        ];

        for (name, value, want) in rows {
            // Act
            let got = is_enabled(value);

            // Assert
            assert_eq!(got, want, "row `{name}`: wrong guard state for {value:?}");
        }
    }

    /// # Design promise
    /// AC-001-15 / INV-15: with test mode on, only a canonical HOME strictly inside the system temp
    /// directory is accepted; every refusal names the offending HOME. With test mode off nothing is
    /// restricted.
    ///
    /// # Scenario (Given)
    /// temp dir `/var/folders/ab/T`. Rows: mode off + real home; on + shallow inside; on + deep
    /// inside; on + real home; on + `T-evil/x` (string-prefix lookalike); on + `T` itself; on + the
    /// parent of `T`; on + `T/../../../Users/real` (`..` escape); on + relative `tmp123`.
    ///
    /// # Action (When)
    /// `check(test_mode, home, temp)` for each row.
    ///
    /// # Expected (Then)
    /// Off/inside rows -> `Ok`. All other on-rows -> `Err(v)` with `v.home == home` and
    /// `v.to_string()` containing the home path text.
    ///
    /// # Must never
    /// Accept the real home in test mode; accept `T-evil` by string prefix; accept `T` itself.
    ///
    /// # Would catch
    /// `home.to_str().starts_with(temp)`; `starts_with` without the strictness; trusting `..`.
    ///
    /// # Why this test (not redundant)
    /// The whole decision table of the pure function; the CLI test checks only the wiring.
    #[test]
    fn ac_001_15_test_mode_refuses_homes_outside_the_system_temp_dir() {
        // Arrange
        let temp = Path::new("/var/folders/ab/T");
        let rows: [(&str, bool, &str, bool); 9] = [
            ("off-real-home", false, "/Users/real", true),
            ("on-inside", true, "/var/folders/ab/T/tmp123", true),
            ("on-deep-inside", true, "/var/folders/ab/T/a/b/c", true),
            ("on-real-home", true, "/Users/real", false),
            (
                "on-prefix-lookalike",
                true,
                "/var/folders/ab/T-evil/x",
                false,
            ),
            ("on-equals-temp", true, "/var/folders/ab/T", false),
            ("on-parent-of-temp", true, "/var/folders/ab", false),
            (
                "on-dotdot-escape",
                true,
                "/var/folders/ab/T/../../../Users/real",
                false,
            ),
            ("on-relative", true, "tmp123", false),
        ];

        for (name, mode, home, accepted) in rows {
            // Act
            let got = check(mode, Path::new(home), temp);

            // Assert
            if accepted {
                assert!(got.is_ok(), "row `{name}`: expected Ok, got {got:?}");
            } else {
                let v = got.expect_err(&format!("row `{name}`: INV-15 violation must be refused"));
                assert_eq!(
                    v.home,
                    Path::new(home),
                    "row `{name}`: violation must carry the home"
                );
                assert!(
                    v.to_string().contains(home),
                    "row `{name}`: message must name the offending HOME, got {:?}",
                    v.to_string()
                );
            }
        }
    }
}
