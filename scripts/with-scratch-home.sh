#!/usr/bin/env bash
# scripts/with-scratch-home.sh <command...>
# Runs a command (normally cargo test/nextest/llvm-cov/mutants) with a throw-away $HOME and
# CLEANER_TEST_MODE=1 so tests can never see or touch the developer's real home (INV-15).
# CARGO_HOME/RUSTUP_HOME keep pointing at the real toolchain so builds still work.
set -eu
[ $# -gt 0 ] || { echo "usage: $0 <command...>" >&2; exit 2; }
real_home="$HOME"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cleaner-scratch-home.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
export CARGO_HOME="${CARGO_HOME:-$real_home/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$real_home/.rustup}"
export HOME="$scratch"
export CLEANER_TEST_MODE=1
"$@"
