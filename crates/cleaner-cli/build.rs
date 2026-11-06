//! Embeds the build identity shown by `cleaner --version`: git SHA and target triple.
//!
//! Deterministic and offline: the SHA comes from `CLEANER_GIT_SHA` if set, else from the local
//! `git rev-parse` (no network), else `unknown`. No build date is embedded at all, so there is
//! nothing for `SOURCE_DATE_EPOCH` to influence and identical sources build identical binaries.

use std::process::Command;

fn git_sha() -> String {
    if let Ok(sha) = std::env::var("CLEANER_GIT_SHA") {
        return sha;
    }
    // Build-script-only use of `Command` (clippy.toml bans it at runtime: INV-01/INV-10). It runs
    // a read-only local `git` at compile time; it is not part of the shipped binary.
    #[allow(clippy::disallowed_methods)]
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output();
    output
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=CLEANER_GIT_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rustc-env=CLEANER_GIT_SHA={}", git_sha());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=CLEANER_TARGET={target}");
}
