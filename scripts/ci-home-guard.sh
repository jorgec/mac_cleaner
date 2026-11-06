#!/usr/bin/env bash
# scripts/ci-home-guard.sh - CI assertion for INV-15 ("tests never touch the real machine").
#
#   ci-home-guard.sh snapshot FILE   record a fingerprint of the real $HOME
#   ci-home-guard.sh verify FILE     fail if the fingerprint changed, or if the cleaner's
#                                    log directory appeared under the real home
#
# The fingerprint is a hash of the *names* (not contents or mtimes) of the top two levels of
# $HOME, excluding toolchain/cache directories that CI legitimately writes (.cargo, .rustup,
# .cache, .npm, .config, .local, .docker, .gradle, Library). Library is covered separately by
# the explicit ~/Library/Logs/mac-cleaner check. bash 3.2 compatible.
set -u -o pipefail

fingerprint() {
  (
    cd "${REAL_HOME:-$HOME}" || exit 1
    find . -maxdepth 2 \
      \( -path ./.cargo -o -path ./.rustup -o -path ./.cache -o -path ./.npm -o -path ./.config \
      -o -path ./.local -o -path ./.docker -o -path ./.gradle -o -path ./Library \) -prune -o -print \
      | LC_ALL=C sort | shasum -a 256 | cut -d' ' -f1
  )
}

mode="${1:-}"
file="${2:-}"
if [ -z "$mode" ] || [ -z "$file" ]; then
  echo "usage: $0 snapshot|verify FILE" >&2
  exit 2
fi

case "$mode" in
  snapshot)
    fingerprint >"$file"
    echo "home-guard: snapshot recorded ($(cat "$file"))"
    ;;
  verify)
    now="$(fingerprint)"
    if [ "$now" != "$(cat "$file")" ]; then
      echo "home-guard: FAIL: real HOME contents changed during tests (INV-15)" >&2
      exit 1
    fi
    if [ -e "${REAL_HOME:-$HOME}/Library/Logs/mac-cleaner" ]; then
      echo "home-guard: FAIL: ~/Library/Logs/mac-cleaner exists in the real HOME (INV-15)" >&2
      exit 1
    fi
    echo "home-guard: OK: real HOME untouched"
    ;;
  *)
    echo "usage: $0 snapshot|verify FILE" >&2
    exit 2
    ;;
esac
