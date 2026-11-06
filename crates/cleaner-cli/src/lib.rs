//! Library half of the CLI crate (spec 002b). `main.rs` is the composition root (the only place
//! that reads the process environment and wires real adapters); everything that can be decided
//! without I/O lives here so it can be unit-tested against canned reports:
//!
//! * [`args`] - the `clap` surface (`cleaner scan [--rule ID]... [--tier T] [--top N] [--json]`),
//! * [`select`] - rule selectors (AC-002-14),
//! * [`render`] - byte units and the human report (AC-002-16, AC-002-7 hint),
//! * [`fda`] - which terminal application the Full Disk Access hint names,
//! * [`ids`] - the production [`cleaner_core::ports::RunIds`] (ULID),
//! * [`scan_cmd`] - the `scan` composition (adapters, SIGINT, audit, rendering),
//! * [`seams`] - the hermetic test seams `CLEANER_TMUTIL` / `CLEANER_TEST_VOLUME`.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

pub mod args;
pub mod fda;
pub mod ids;
pub mod render;
pub mod scan_cmd;
pub mod seams;
pub mod select;

/// `<version> (<git-sha> <target-triple>)`, embedded by `build.rs`; clap prefixes the binary name,
/// so `cleaner --version` prints `cleaner 0.0.0 (abc123 aarch64-apple-darwin)` (spec 001).
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CLEANER_GIT_SHA"),
    " ",
    env!("CLEANER_TARGET"),
    ")"
);
