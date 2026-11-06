//! Which terminal application the Full Disk Access hint names (spec 002 AC-002-7).
//!
//! # Worksheet - `fda::terminal_app`
//! ```text
//! Function:        cleaner_cli::fda::terminal_app(Option<&str>) -> String      (input: $TERM_PROGRAM)
//! Contract:        Apple_Terminal -> Terminal; iTerm.app -> iTerm; vscode -> Visual Studio Code;
//!                  ghostty -> Ghostty; WezTerm -> WezTerm; unset, empty or unknown -> `your terminal
//!                  app`. The result is never empty. (AC-002-7: name the terminal app, not the binary)
//! Equivalence classes: each known program | unset | empty | unknown value
//! Must-never:      return an empty name; echo an arbitrary environment value into the hint verbatim
//!                  (it could be hostile text)
//! Selected tests:  ac_002_7_terminal_app_is_named_from_term_program_with_a_generic_fallback
//! Deliberately not tested: terminals outside the table (they get the generic text by design).
//! ```

use cleaner_cli::fda::terminal_app;

/// # Design promise
/// AC-002-7: the Full Disk Access hint names the application the user must add in System Settings (the
/// terminal), derived from `$TERM_PROGRAM`; when it cannot be known the hint says `your terminal app`
/// rather than guessing or printing the raw environment value.
///
/// # Scenario (Given)
/// Rows: the five known `TERM_PROGRAM` values, unset, empty, and an unknown/hostile value.
///
/// # Action (When)
/// `terminal_app(value)` per row.
///
/// # Expected (Then)
/// `Terminal`, `iTerm`, `Visual Studio Code`, `Ghostty`, `WezTerm`, then `your terminal app` for unset,
/// empty and the unknown value (`evil\u{1b}[31m` is not echoed).
///
/// # Must never
/// Return an empty string; echo an unknown value (terminal-escape injection through the environment).
///
/// # Would catch
/// A stub returning `""`, `unwrap_or(raw)` fallbacks, mapping `Apple_Terminal` to itself (the user
/// would look for an app of that name).
///
/// # Why this test (not redundant)
/// The only test of the name table; the hint's wording and trigger are in `render.rs`.
#[test]
fn ac_002_7_terminal_app_is_named_from_term_program_with_a_generic_fallback() {
    // Arrange
    let rows: [(Option<&str>, &str); 8] = [
        (Some("Apple_Terminal"), "Terminal"),
        (Some("iTerm.app"), "iTerm"),
        (Some("vscode"), "Visual Studio Code"),
        (Some("ghostty"), "Ghostty"),
        (Some("WezTerm"), "WezTerm"),
        (None, "your terminal app"),
        (Some(""), "your terminal app"),
        (Some("evil\u{1b}[31m"), "your terminal app"),
    ];

    for (input, want) in rows {
        // Act
        let got = terminal_app(input);

        // Assert
        assert_eq!(got, want, "terminal_app({input:?})");
    }
}
