//! Calls every method banned by the repo-root `clippy.toml`. Expected to FAIL clippy.
//! Never run: these functions exist only to be linted, and are never called.
#![allow(dead_code)]

use std::path::Path;

pub fn violates_all(p: &Path) {
    let _ = std::fs::remove_file(p);
    let _ = std::fs::remove_dir(p);
    let _ = std::fs::remove_dir_all(p);
    let _ = std::fs::rename(p, p);
    let _ = std::fs::write(p, b"");
    let _ = std::fs::copy(p, p);
    let _ = std::process::Command::new("true");
}
