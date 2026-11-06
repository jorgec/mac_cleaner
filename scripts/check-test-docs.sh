#!/usr/bin/env bash
# scripts/check-test-docs.sh - enforce .claude/skills/cleaner-orchestrator/references/testing-policy.md
#
# Rules checked for every test function (a fn preceded by #[test]-style attribute, or a fn
# inside a `proptest! { ... }` block):
#   1. It has a rustdoc (`///`) containing ALL seven headings, in this order:
#        # Design promise | # Scenario (Given) | # Action (When) | # Expected (Then)
#        # Must never | # Would catch | # Why this test (not redundant)
#   2. Every assert!/assert_eq!/assert_ne!/debug_assert!/debug_assert_eq!/debug_assert_ne!
#      in its body has a message argument (assert! needs >= 2 args; the _eq/_ne forms >= 3).
#
# Usage: scripts/check-test-docs.sh [FILE_OR_DIR ...]      (default: crates/ and tests/)
# Exit:  0 = clean, or no test functions found (a note is printed); 1 = violations; 2 = usage.
# Output: one line per violation, "path:LINE: message".
# Portability: bash 3.2 + BSD/POSIX awk (no gawk extensions).
#
# KNOWN LIMITS (it is a line scanner, not a parser; upgrade to a syn-based checker if flaky):
#   - Only the heading *presence and order* is checked, not that the sections are non-hollow.
#   - Attributes spanning several lines (#[cfg_attr(\n...\n)]) are not recognised as test attrs.
#   - Single-line `#[test] fn f() {..}` and `#[test]` on the same line as other code are missed.
#   - Raw strings are handled (r"..", r#".."#) but byte-raw strings (br"..") are not.
#   - Commas inside generics at the top level of an assert (`assert_eq!(f::<A, B>(), 1)`)
#     are counted as argument separators, which can hide a missing message.
#   - Asserts written with brace delimiters (assert!{..}) or inside helper fns that are not
#     themselves tests are not checked. `assert_matches!`/`matches!` are out of scope.
#   - Macro-generated tests (macro_rules!) are invisible.
set -u -o pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  -h | --help)
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

targets=()
if [ "$#" -gt 0 ]; then
  for a in "$@"; do targets+=("$a"); done
else
  [ -d "$root/crates" ] && targets+=("$root/crates")
  [ -d "$root/tests" ] && targets+=("$root/tests")
fi

files=()
if [ "${#targets[@]}" -gt 0 ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && files+=("$f")
  done < <(
    for t in "${targets[@]}"; do
      if [ -d "$t" ]; then
        find "$t" -type f -name '*.rs' -not -path '*/target/*' -not -path '*/tests/lint/*'
      elif [ -f "$t" ]; then
        printf '%s\n' "$t"
      else
        echo "check-test-docs: no such file or directory: $t" >&2
        exit 2
      fi
    done | sort
  )
fi

if [ "${#files[@]}" -eq 0 ]; then
  echo "check-test-docs: note: no Rust files found; nothing to check."
  exit 0
fi

awk '
function sanitize(line,   out, i, n, c, c2, j, k, h, pc, rest) {
  # Blank out comments and the contents of string/char literals, keeping quotes and
  # structure, so brace/paren/comma counting is not fooled. State persists across lines.
  out = ""; n = length(line); i = 1
  while (i <= n) {
    c = substr(line, i, 1); c2 = substr(line, i + 1, 1)
    if (in_block > 0) {
      if (c == "*" && c2 == "/") { in_block--; i += 2; out = out "  "; continue }
      if (c == "/" && c2 == "*") { in_block++; i += 2; out = out "  "; continue }
      out = out " "; i++; continue
    }
    if (in_raw) {
      if (c == "\"" && substr(line, i, length(raw_term)) == raw_term) {
        out = out raw_term; i += length(raw_term); in_raw = 0; continue
      }
      out = out " "; i++; continue
    }
    if (in_str) {
      if (c == "\\") { out = out "  "; i += 2; continue }
      if (c == "\"") { in_str = 0; out = out "\""; i++; continue }
      out = out " "; i++; continue
    }
    if (c == "/" && c2 == "/") break
    if (c == "/" && c2 == "*") { in_block = 1; out = out "  "; i += 2; continue }
    if (c == "\"") { in_str = 1; out = out "\""; i++; continue }
    if (c == "r") {
      pc = (i > 1) ? substr(line, i - 1, 1) : " "
      if (pc !~ /[A-Za-z0-9_]/) {
        j = i + 1; h = 0
        while (substr(line, j, 1) == "#") { h++; j++ }
        if (substr(line, j, 1) == "\"") {
          raw_term = "\""
          for (k = 0; k < h; k++) raw_term = raw_term "#"
          in_raw = 1; out = out "\""; i = j + 1; continue
        }
      }
    }
    if (c == "\047") {
      if (c2 == "\\") {
        j = i + 3
        while (j <= n && substr(line, j, 1) != "\047") j++
        out = out "\047 \047"; i = j + 1; continue
      }
      if (substr(line, i + 2, 1) == "\047") { out = out "\047 \047"; i += 3; continue }
    }
    out = out c; i++
  }
  return out
}

function reset_file() {
  in_block = 0; in_str = 0; in_raw = 0; raw_term = ""
  gd = 0; fn_test = 0; started = 0; fn_depth = 0
  in_pt = 0; pt_started = 0; pt_depth = 0
  ap = 0; pend_test = 0
  split("", doc_idx); ndoc = 0
}

function violation(ln, msg) {
  printf "%s:%d: %s\n", FILENAME, ln, msg > "/dev/stderr"
  nviol++
}

function check_doc(ln, name,   i, miss, last, bad) {
  miss = ""; last = 0; bad = 0
  for (i = 1; i <= 7; i++) {
    if (!(H[i] in doc_idx)) miss = miss (miss == "" ? "" : ", ") H[i]
    else {
      if (doc_idx[H[i]] < last) bad = 1
      last = doc_idx[H[i]]
    }
  }
  if (ndoc == 0) {
    violation(ln, "test fn `" name "` has no rustdoc; it needs all seven testing-policy headings")
  } else if (miss != "") {
    violation(ln, "test fn `" name "` rustdoc is missing heading(s): " miss)
  } else if (bad) {
    violation(ln, "test fn `" name "` rustdoc headings are out of the required order")
  }
}

BEGIN {
  H[1] = "# Design promise"; H[2] = "# Scenario (Given)"; H[3] = "# Action (When)"
  H[4] = "# Expected (Then)"; H[5] = "# Must never"; H[6] = "# Would catch"
  H[7] = "# Why this test (not redundant)"
  nviol = 0; ntests = 0; nasserts = 0; nfiles = 0
  TESTATTR = "^[[:space:]]*#\\[[[:space:]]*(test|rstest|test_case|proptest|[A-Za-z_:]*::test)([^A-Za-z0-9_]|$)"
}

FNR == 1 { reset_file(); nfiles++ }

{
  raw = $0
  at_clean = (in_block == 0 && !in_str && !in_raw)

  # Doc comment lines (`///` but not `////`): accumulate, never reset by them.
  if (at_clean && raw ~ /^[[:space:]]*\/\/\// && raw !~ /^[[:space:]]*\/\/\/\//) {
    t = raw
    sub(/^[[:space:]]*\/\/\/[[:space:]]?/, "", t)
    sub(/[[:space:]]+$/, "", t)
    ndoc++
    if (t ~ /^# /) doc_idx[t] = ndoc
    next
  }

  s = sanitize(raw)
  if (s ~ /^[[:space:]]*$/) next

  # Attribute lines keep the pending doc (docs may sit above or between attributes).
  if (ap == 0 && s ~ /^[[:space:]]*#\[/) {
    if (s ~ TESTATTR) pend_test = 1
    next
  }

  # A code line. Decide whether it declares a test fn.
  if (ap == 0 && match(s, /(^|[^A-Za-z0-9_])fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
    decl = substr(s, RSTART, RLENGTH)
    sub(/^.*fn[[:space:]]+/, "", decl)
    is_pt_fn = (in_pt && pt_started && gd == pt_depth + 1)
    if ((pend_test || is_pt_fn) && !fn_test) {
      fn_test = 1; started = 0; fn_depth = gd; ntests++
      check_doc(FNR, decl)
    }
  }
  if (ap == 0 && s ~ /proptest![[:space:]]*\{/) { in_pt = 1; pt_started = 0; pt_depth = gd }

  n = length(s); i = 1
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "{") {
      gd++
      if (fn_test && !started) started = 1
      if (in_pt && !pt_started && gd == pt_depth + 1) pt_started = 1
    } else if (c == "}") {
      gd--
      if (started && gd == fn_depth) { fn_test = 0; started = 0 }
      if (pt_started && gd == pt_depth) { in_pt = 0; pt_started = 0 }
    }

    if (ap > 0) {
      if (c ~ /[([{]/) { ap++; if (!have) { have = 1; args++ } }
      else if (c ~ /[])}]/) {
        ap--
        if (ap == 0) {
          nasserts++
          if (args < need) {
            violation(aline, "`" aname "!` has no message argument (testing-policy: every assertion explains the broken promise)")
          }
        } else if (!have) { have = 1; args++ }
      }
      else if (c == "," && ap == 1) have = 0
      else if (c !~ /[[:space:]]/) { if (!have) { have = 1; args++ } }
      i++; continue
    }

    if (started && (c == "a" || c == "d")) {
      pc = (i > 1) ? substr(s, i - 1, 1) : " "
      if (pc !~ /[A-Za-z0-9_]/) {
        rest = substr(s, i)
        if (match(rest, /^(debug_)?assert(_eq|_ne)?![[:space:]]*[([]/)) {
          aname = substr(rest, 1, index(rest, "!") - 1)
          need = (aname ~ /_(eq|ne)$/) ? 3 : 2
          aline = FNR; ap = 1; args = 0; have = 0
          i += RLENGTH; continue
        }
      }
    }
    i++
  }

  # The code line consumed any pending doc / test attribute.
  split("", doc_idx); ndoc = 0; pend_test = 0
}

END {
  if (ntests == 0) {
    print "check-test-docs: note: no test functions found in " nfiles " file(s); nothing to check."
    exit 0
  }
  if (nviol > 0) {
    printf "check-test-docs: FAILED: %d violation(s) across %d test fn(s), %d assertion(s) in %d file(s)\n", nviol, ntests, nasserts, nfiles > "/dev/stderr"
    exit 1
  }
  printf "check-test-docs: OK: %d test fn(s), %d assertion(s) in %d file(s)\n", ntests, nasserts, nfiles
}
' "${files[@]}"
