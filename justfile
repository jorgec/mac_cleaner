# Developer task runner. `just` lists recipes. All recipes are read-only with respect to the
# real machine: tests use temp dirs (INV-15). Requires cargo-nextest, cargo-llvm-cov,
# cargo-mutants, cargo-deny, cargo-audit, shellcheck, actionlint (see scripts/bootstrap.sh).

set shell := ["bash", "-euo", "pipefail", "-c"]

# Minimum line coverage enforced by `just cov`; raise as real code lands (see ci.yml).
cov_min := "0"

default:
    @just --list

# Fast type-check of everything.
check:
    cargo check --workspace --all-targets --locked

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# Clippy as CI runs it, plus proof that the disallowed-methods ban still fires (AC-001-16).
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    scripts/check-lint-sample.sh

# Unit + integration tests (nextest) and doctests.
test:
    scripts/with-scratch-home.sh cargo nextest run --workspace --locked --no-tests=pass
    cargo test --workspace --doc --locked

# Only the safety regression suite (tests whose name contains "safety").
safety:
    scripts/with-scratch-home.sh cargo nextest run --workspace --locked -E 'test(safety)' --no-tests=fail

# Testing-policy enforcement: seven-heading rustdoc + assert messages, and the checker's own tests.
test-docs:
    scripts/check-test-docs.sh
    scripts/tests/check-test-docs.test.sh

cov:
    scripts/with-scratch-home.sh cargo llvm-cov nextest --workspace --locked --no-tests=pass --fail-under-lines {{cov_min}}

# Mutation testing on cleaner-core (slow; also nightly). Pass extra args, e.g. `just mutants --in-diff pr.diff`.
mutants *ARGS:
    cargo mutants --package cleaner-core {{ARGS}}

deny:
    cargo deny check

audit:
    cargo audit

docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# Static analysis of scripts and workflows.
lint-scripts:
    shellcheck scripts/*.sh scripts/tests/*.sh
    actionlint

# Everything CI runs (except msrv and the mutants-on-diff job), in CI order.
ci: fmt-check lint test safety test-docs deny audit cov docs lint-scripts
