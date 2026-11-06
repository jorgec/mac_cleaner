# ADR 0001 – Cargo workspace with hexagonal (ports & adapters) architecture

Status: Accepted · Date: 2026-11-06

## Context
The tool will eventually delete user data. Correctness of the deletion path must be provable
with fast tests that never touch the real machine (INV-15), and "which code can mutate the
disk" must be a small, auditable set.

## Options
1. Single crate, modules. Simple, but nothing stops macOS-specific or mutating code leaking
   into logic, and `cargo test` compile times grow with FFI deps.
2. **Workspace: `cleaner-core` (pure logic + port traits), `cleaner-macos` (real adapters),
   `cleaner-cli` (clap, rendering, composition root), `cleaner-testkit` (dev-only fixtures).**
3. Core as a dynamic plugin system. Over-engineered.

## Decision
Option 2. Dependencies point inward: `cli → macos → core`; `testkit` is a dev-dependency only.
- `core`: `#![forbid(unsafe_code)]`; no `std::env`, no `home_dir()`, no process spawning, no
  direct `std::fs` mutation. All effects via ports: `Fs`, `Clock`, `RunIds`, `CommandRunner`,
  `VolumeCapacity`, `AuditSink` (later: `Trasher`, `Prompter`).
- `macos`: the only crate that may contain `unsafe` (FFI), each block with `// SAFETY:` + test.
- `cli`: the composition root reads `HOME`/env once and injects it.
- `clippy.toml` `disallowed-methods` bans `std::fs::{remove_file, remove_dir, remove_dir_all,
  rename, write, copy}` and `std::process::Command::new` everywhere except the (future)
  executor module and the `macos` adapters, enforced in CI.
- Rules are data (`Rule` structs in `core::rules::builtin`), one declarative entry each, plus
  a validity test over the whole table (spec 002 AC-002-11).

## Consequences
+ Fast, deterministic tests with in-memory/fake ports; safety logic isolated.
+ One door to mutation can be enforced by lint, not convention.
– More crates and trait boilerplate up front; accepted for the safety payoff.
