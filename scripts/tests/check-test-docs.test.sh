#!/usr/bin/env bash
# scripts/tests/check-test-docs.test.sh - tests for scripts/check-test-docs.sh.
# Proves: the good fixture passes; each bad fixture fails, exits non-zero, and names
# file:line with a clear message; an empty tree passes with a note. bash 3.2 compatible.
set -u -o pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/../check-test-docs.sh"
fx="$here/check-test-docs"
fails=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; fails=$((fails + 1)); }

# expect_status NAME WANT_STATUS OUTPUT_PATTERN... FILE
run_case() {
  local name="$1" want="$2" file="$3"
  shift 3
  local out status
  out="$("$checker" "$file" 2>&1)"
  status=$?
  if [ "$status" -ne "$want" ]; then
    fail "$name: exit $status, wanted $want. Output: $out"
    return
  fi
  local pat
  for pat in "$@"; do
    if ! printf '%s\n' "$out" | grep -Eq -- "$pat"; then
      fail "$name: output lacks /$pat/. Output: $out"
      return
    fi
  done
  pass "$name"
}

run_case "good fixture is accepted" 0 "$fx/good.rs" 'OK: 2 test fn\(s\), 5 assertion\(s\)'

# shellcheck disable=SC2016  # backticks in the expected text are literal
run_case "missing headings are reported with file:line" 1 "$fx/bad_missing_heading.rs" \
  'bad_missing_heading\.rs:20: test fn `ac_000_2_incomplete_docs` rustdoc is missing heading\(s\): # Would catch, # Why this test \(not redundant\)' \
  'bad_missing_heading\.rs:25: test fn `ac_000_3_no_docs_at_all` has no rustdoc'

# shellcheck disable=SC2016  # backticks in the expected text are literal
run_case "assertions without messages are reported with file:line" 1 "$fx/bad_assert_no_message.rs" \
  'bad_assert_no_message\.rs:28: `assert!` has no message argument' \
  'bad_assert_no_message\.rs:29: `assert_eq!` has no message argument' \
  'bad_assert_no_message\.rs:34: `debug_assert!` has no message argument'

# The compliant "assert_ne! ... this one is fine" must NOT be flagged.
out="$("$checker" "$fx/bad_assert_no_message.rs" 2>&1)"
if printf '%s\n' "$out" | grep -q 'assert_ne!'; then
  fail "assert_ne! with a message was wrongly flagged: $out"
else
  pass "assert with message not flagged"
fi

# A tree with Rust files but no tests exits 0 with a note.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '//! no tests here\n' >"$tmp/lib.rs"
out="$("$checker" "$tmp" 2>&1)"
status=$?
if [ "$status" -eq 0 ] && printf '%s\n' "$out" | grep -q 'no test functions found'; then
  pass "no tests: exit 0 with note"
else
  fail "no tests: exit $status, output: $out"
fi

# A directory with no .rs files at all also exits 0 with a note.
empty="$(mktemp -d "$tmp/empty.XXXXXX")"
out="$("$checker" "$empty" 2>&1)"
status=$?
if [ "$status" -eq 0 ] && printf '%s\n' "$out" | grep -q 'no Rust files found'; then
  pass "no files: exit 0 with note"
else
  fail "no files: exit $status, output: $out"
fi

if [ "$fails" -ne 0 ]; then
  echo "check-test-docs.test.sh: $fails failure(s)" >&2
  exit 1
fi
echo "check-test-docs.test.sh: all cases passed"
