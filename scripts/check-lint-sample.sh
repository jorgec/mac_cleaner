#!/usr/bin/env bash
# scripts/check-lint-sample.sh - prove clippy.toml `disallowed-methods` really fires (AC-001-16).
#
# Runs clippy on tests/lint/sample (a deliberately violating crate, excluded from the
# workspace) using the repo-root clippy.toml, and PASSES only if clippy FAILS and reports
# every banned call. If someone weakens clippy.toml, this script goes red.
# Compatible with bash 3.2.
set -u -o pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

if CLIPPY_CONF_DIR="$root" cargo clippy --manifest-path "$root/tests/lint/sample/Cargo.toml" \
  --target-dir "$root/tests/lint/sample/target" --locked -- -D warnings >"$out" 2>&1; then
  cat "$out"
  echo "FAIL: clippy accepted the lint sample; disallowed-methods is not enforcing." >&2
  exit 1
fi

status=0
for m in std::fs::remove_file std::fs::remove_dir std::fs::remove_dir_all std::fs::rename \
  std::fs::write std::fs::copy std::process::Command::new; do
  # Match the exact name followed by a backtick so remove_dir does not match remove_dir_all.
  if ! grep -Fq "use of a disallowed method \`$m\`" "$out"; then
    echo "FAIL: clippy did not report disallowed method $m" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  cat "$out"
  exit 1
fi
echo "OK: clippy rejected all 7 banned calls in tests/lint/sample (as required)."
