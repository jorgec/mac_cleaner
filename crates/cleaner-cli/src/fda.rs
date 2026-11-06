//! Which application the Full Disk Access hint names (AC-002-7): the **terminal app** that runs
//! `cleaner` (macOS grants Full Disk Access to that app, never to the binary).

/// Name used when `$TERM_PROGRAM` is unset, empty or not in the table.
const GENERIC: &str = "your terminal app";

/// Name to put in the hint for the terminal identified by `$TERM_PROGRAM`.
///
/// Contract: `Apple_Terminal` -> `Terminal`; `iTerm.app` -> `iTerm`; `vscode` -> `Visual Studio
/// Code`; `ghostty` -> `Ghostty`; `WezTerm` -> `WezTerm`; unset, empty or any other value -> the
/// generic `your terminal app`. The result is never empty and an unknown value is never echoed
/// (it comes from the environment and could carry escape sequences). Pure.
#[must_use]
pub fn terminal_app(term_program: Option<&str>) -> String {
    match term_program {
        Some("Apple_Terminal") => "Terminal",
        Some("iTerm.app") => "iTerm",
        Some("vscode") => "Visual Studio Code",
        Some("ghostty") => "Ghostty",
        Some("WezTerm") => "WezTerm",
        _ => GENERIC,
    }
    .to_owned()
}
