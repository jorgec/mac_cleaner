#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Pure domain logic and port traits (hexagonal core). No I/O, no env, no unsafe.
//!
//! Spec 001 surface: [`ports`] (effect traits), [`safety`] (`SafetyGuard`), [`audit`]
//! (JSONL records, sink port, retention logic) and [`testmode`] (INV-15 decision function).
//!
//! Spec 002a surface (the scan core): [`rules`] (rule data and claim logic), [`volume`] (purgeable
//! arithmetic), [`snapshots`] (`tmutil` parsing and orchestration), [`report`] (the `scan/1`
//! model), [`scan`] (the read-only scanner) and [`cancel`] (cooperative cancellation).

pub mod audit;
pub mod cancel;
pub mod ports;
pub mod report;
pub mod rules;
pub mod safety;
pub mod scan;
pub mod snapshots;
pub mod testmode;
pub mod volume;
