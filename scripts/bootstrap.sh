#!/usr/bin/env bash
# scripts/bootstrap.sh – install and verify the dev toolchain for the mac cleaner project.
#
# Target: Apple Silicon macOS (aarch64-apple-darwin). Compatible with the stock macOS
# /bin/bash 3.2 (no associative arrays, mapfile, or ${var,,}).
#
# Guarantees (mirrors the project's own safety posture):
#   * Idempotent: every component is CHECKED first; only missing ones are installed.
#   * Never calls sudo itself. (Homebrew's own installer may ask for your password.)
#   * Never runs downloaded code without consent: remote installers (Homebrew, rustup-init)
#     require an interactive "yes" or the explicit --allow-remote-installers flag. rustup-init
#     is checksum-verified before it runs; the Homebrew script is saved, hashed, and can be
#     viewed first.
#   * Non-interactive without --yes is REPORT-ONLY, never installs.
#   * Everything it does is logged to ~/Library/Logs/mac-cleaner-dev/bootstrap-<ts>.log.
#   * Does not edit shell profiles unless --modify-path is given.
#
# Usage: scripts/bootstrap.sh [options]     (see --help)

set -u -o pipefail

BOOTSTRAP_VERSION="1.0.0"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------- component registry
# id|tier|depends-on|description      (tier: required | recommended | optional)
COMPONENTS='
clt|required|-|Xcode Command Line Tools (compiler/linker, git, codesign)
rustup|required|clt|rustup, the Rust toolchain manager
toolchain|required|rustup|Rust toolchain (rust-toolchain.toml channel, else stable) + stable for tools
rust-components|required|toolchain|rustfmt, clippy, llvm-tools-preview
rust-target|required|toolchain|aarch64-apple-darwin target
brew|recommended|clt|Homebrew package manager
cargo-nextest|recommended|toolchain|test runner
cargo-llvm-cov|recommended|rust-components|coverage
cargo-mutants|recommended|toolchain|mutation testing (finds redundant tests)
cargo-deny|recommended|toolchain|license/advisory/ban checks
cargo-audit|recommended|toolchain|RustSec vulnerability audit
shellcheck|recommended|brew|shell script linter
actionlint|recommended|brew|GitHub Actions workflow linter
just|recommended|brew|task runner
cargo-fuzz|optional|toolchain|fuzzing (needs a nightly toolchain to run)
cargo-cyclonedx|optional|toolchain|SBOM generation for releases
hyperfine|optional|brew|CLI benchmarking
tart|optional|brew|macOS VM runner for destructive-test sandbox
'

# ---------------------------------------------------------------- defaults / state
MODE=install          # install | check
DRY_RUN=0
ASSUME_YES=0
INTERACTIVE=0
ALLOW_REMOTE=0
WITH_OPTIONAL=0
REQUIRED_ONLY=0
MODIFY_PATH=0
ALLOW_UNSUPPORTED=0
ONLY=""
SKIP=""
CLT_WAIT="${BOOTSTRAP_CLT_WAIT:-900}"    # seconds to wait for the CLT GUI installer
RESULTS=""                               # lines: id|status|detail
FORCED_CHECK_REASON=""
LOG_DIR="${BOOTSTRAP_LOG_DIR:-$HOME/Library/Logs/mac-cleaner-dev}"
LOG_FILE=""
TMP_DIR=""

# ---------------------------------------------------------------- output helpers
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_OFF=""
fi

strip_ansi() { sed $'s/\033\\[[0-9;]*m//g'; }
log_line() { [ -n "$LOG_FILE" ] && printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" | strip_ansi >> "$LOG_FILE"; return 0; }
say()  { printf '%s\n' "$*"; log_line "$*"; }
warn() { printf '%s\n' "${C_YEL}warning:${C_OFF} $*" >&2; log_line "warning: $*"; }
die()  { printf '%s\n' "${C_RED}error:${C_OFF} $1" >&2; log_line "error: $1"; exit "${2:-1}"; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

usage() {
  cat <<'EOF'
bootstrap.sh – install/verify the dev toolchain for the mac cleaner (Apple Silicon).

Modes
  (default)             Check each component; offer to install what is missing.
  --check               Report only. Change nothing. Exit 1 if a required tool is missing.
  --dry-run             Show what WOULD be installed (commands, no execution, no downloads).

Interactivity
  (default on a TTY)    Prompts per component: [Y/n/a/q]  a = yes to all remaining
                        required/recommended, q = quit. Optional tools default to No.
  --yes, -y             Non-interactive: install required + recommended without prompting.
  --non-interactive     Never prompt. Without --yes this degrades to --check.
                        (Also implied when stdin/stdout is not a TTY, or CI is set.)

Selection
  --with-optional       Also install optional tools in --yes/--dry-run runs.
  --required-only       Only handle required components.
  --only a,b,c          Only these component ids.      --skip a,b   Exclude these ids.
  --list                Print component ids and exit.

Consent / behavior
  --allow-remote-installers
                        Pre-authorize downloading Homebrew's installer and rustup-init
                        (needed for unattended installs of those two; otherwise skipped).
  --modify-path         Let rustup-init edit your shell profile (default: it does not;
                        the script prints the line to add instead).
  --allow-unsupported   Proceed on non-arm64 / Rosetta / non-macOS hosts (not recommended).
  -h, --help            This help.      --version   Print script version.

Environment
  BOOTSTRAP_LOG_DIR     Log directory (default ~/Library/Logs/mac-cleaner-dev)
  BOOTSTRAP_CLT_WAIT    Seconds to wait for Command Line Tools install (default 900)
  NO_COLOR              Disable colors

Exit codes
  0 everything selected is present   1 a required component is missing/failed
  2 usage error   3 unsupported platform   4 partial (recommended/optional missing or skipped,
  or aborted by user)   130 interrupted
EOF
}

# ---------------------------------------------------------------- cleanup / signals
# shellcheck disable=SC2329  # invoked via trap
cleanup() { [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT
trap 'say "Interrupted."; exit 130' INT TERM

# ---------------------------------------------------------------- argument parsing
need_val() { [ $# -ge 2 ] && [ -n "$2" ] || die "option $1 needs a value" 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --non-interactive) INTERACTIVE=-1 ;;
    --with-optional) WITH_OPTIONAL=1 ;;
    --required-only) REQUIRED_ONLY=1 ;;
    --allow-remote-installers) ALLOW_REMOTE=1 ;;
    --modify-path) MODIFY_PATH=1 ;;
    --allow-unsupported) ALLOW_UNSUPPORTED=1 ;;
    --only) need_val "$@"; ONLY="$2"; shift ;;
    --skip) need_val "$@"; SKIP="$2"; shift ;;
    --list) printf '%s' "$COMPONENTS" | awk -F'|' 'NF>=4 {printf "%-16s %-12s %s\n",$1,$2,$4}'; exit 0 ;;
    --version) echo "bootstrap.sh $BOOTSTRAP_VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# Validate ids passed to --only/--skip so typos fail loudly instead of silently doing nothing.
known_ids=$(printf '%s' "$COMPONENTS" | awk -F'|' 'NF>=4 {print $1}')
for list in "$ONLY" "$SKIP"; do
  [ -z "$list" ] && continue
  oldifs=$IFS; IFS=,
  for id in $list; do
    printf '%s\n' "$known_ids" | grep -qx "$id" || { IFS=$oldifs; die "unknown component id: $id (see --list)" 2; }
  done
  IFS=$oldifs
done

# Interactivity: a TTY on stdin+stdout, not CI, and not forced off.
if [ "$INTERACTIVE" != -1 ] && [ -t 0 ] && [ -t 1 ] && [ -z "${CI:-}" ]; then INTERACTIVE=1; else INTERACTIVE=0; fi

# Safe default: if we cannot ask and were not told "yes", never install.
if [ "$MODE" = install ] && [ "$DRY_RUN" = 0 ] && [ "$INTERACTIVE" = 0 ] && [ "$ASSUME_YES" = 0 ]; then
  MODE=check
  FORCED_CHECK_REASON="non-interactive run without --yes: reporting only (pass --yes to install)"
fi
[ "$DRY_RUN" = 1 ] && ASSUME_YES=1   # dry-run never prompts

# ---------------------------------------------------------------- logging setup
umask 077
mkdir -p "$LOG_DIR" 2>/dev/null && chmod 700 "$LOG_DIR" 2>/dev/null
LOG_FILE="$LOG_DIR/bootstrap-$(date +%Y%m%d-%H%M%S).log"
: > "$LOG_FILE" 2>/dev/null || { LOG_FILE=""; warn "cannot write log under $LOG_DIR; continuing without a log file"; }
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cleaner-bootstrap.XXXXXX")" || die "cannot create temp dir"

# ---------------------------------------------------------------- generic helpers
status_of() { printf '%s' "$RESULTS" | grep "^$1|" | tail -1 | cut -d'|' -f2; }
set_status() { RESULTS="${RESULTS}$1|$2|$3"$'\n'; }
is_satisfied() { case "$1" in present|installed) return 0 ;; *) return 1 ;; esac; }
in_list() { case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
fetch() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --output "$2" "$1"; }

# Run a command, show + log its output. Honors --dry-run. Returns the command's exit code.
run() {
  say "${C_DIM}+ $*${C_OFF}"
  [ "$DRY_RUN" = 1 ] && return 0
  "$@" 2>&1 | tee -a "${LOG_FILE:-/dev/null}"
  return "${PIPESTATUS[0]}"
}
# Same, but attached to the terminal (for installers that prompt, e.g. sudo/password).
run_tty() {
  say "${C_DIM}+ $* (interactive)${C_OFF}"
  [ "$DRY_RUN" = 1 ] && return 0
  "$@"
  local rc=$?
  log_line "exit status $rc: $*"
  return $rc
}

load_env() {   # make already-installed tools visible to this script (does not touch your profile)
  # shellcheck disable=SC1091
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
  local b
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$b" ]; then eval "$("$b" shellenv)"; break; fi
  done
  hash -r 2>/dev/null
  return 0
}

confirm() {   # confirm "question" [default y|n]
  local q="$1" def="${2:-y}" ans hint
  if [ "$ASSUME_YES" = 1 ]; then return 0; fi
  [ "$INTERACTIVE" = 1 ] || return 1
  if [ "$def" = y ]; then hint='[Y/n/a/q]'; else hint='[y/N/a/q]'; fi
  while :; do
    printf '%s %s ' "$q" "$hint"
    IFS= read -r ans || ans=q
    ans=$(lower "$ans"); [ -z "$ans" ] && ans=$def
    case "$ans" in
      y|yes) log_line "prompt: $q -> yes"; return 0 ;;
      n|no)  log_line "prompt: $q -> no";  return 1 ;;
      a|all) log_line "prompt: $q -> yes-to-all"; ASSUME_YES=1; return 0 ;;
      q|quit) log_line "prompt: $q -> quit"; say "Aborted by user."; ABORTED=1; finish ;;
      *) echo "Please answer y, n, a (yes to all remaining), or q (quit)." ;;
    esac
  done
}

# Consent for running downloaded code. Interactive "yes" or --allow-remote-installers only.
remote_consent() {   # remote_consent name url
  [ "$ALLOW_REMOTE" = 1 ] && return 0
  [ "$DRY_RUN" = 1 ] && return 0
  [ "$INTERACTIVE" = 1 ] || return 1
  say "$1 is installed by downloading and running code from:"
  say "    $2"
  ASSUME_YES_SAVED=$ASSUME_YES; ASSUME_YES=0      # 'yes to all' must not cover remote code
  confirm "Download and run it?" n; local rc=$?
  ASSUME_YES=$ASSUME_YES_SAVED
  return $rc
}

project_channel() {   # rust-toolchain.toml channel if pinned, else stable
  local f="$REPO_ROOT/rust-toolchain.toml" ch=""
  [ -f "$f" ] && ch=$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -1)
  printf '%s' "${ch:-stable}"
}

# ---------------------------------------------------------------- per-component checks
# Each check prints a short detail (usually a version) on stdout and returns 0 if present.

check_clt() {
  # Order matters: with no CLT installed, running /usr/bin/cc or git can pop up Apple's
  # installer dialog, so confirm the developer dir exists first.
  local p
  p=$(xcode-select -p 2>/dev/null) || return 1
  [ -d "$p" ] || return 1
  cc --version >/dev/null 2>&1 || return 1          # also fails if the Xcode license is unaccepted
  command -v git >/dev/null 2>&1 || return 1
  command -v codesign >/dev/null 2>&1 || return 1
  printf '%s' "$p"
}
check_rustup() { command -v rustup >/dev/null 2>&1 && rustup --version 2>/dev/null | head -1; }
check_toolchain() {
  # Uses explicit toolchain names (never the cwd proxy) so a check can never trigger an auto-install.
  command -v rustup >/dev/null 2>&1 || return 1
  local ch; ch=$(project_channel)
  rustup toolchain list 2>/dev/null | grep -q "^$ch" || return 1
  rustup toolchain list 2>/dev/null | grep -q '^stable' || return 1
  rustup run "$ch" rustc --version 2>/dev/null
}
check_rust_components() {
  command -v rustup >/dev/null 2>&1 || return 1
  local ch out; ch=$(project_channel)
  out=$(rustup component list --installed --toolchain "$ch" 2>/dev/null) || return 1
  printf '%s\n' "$out" | grep -q '^rustfmt' || return 1
  printf '%s\n' "$out" | grep -q '^clippy' || return 1
  printf '%s\n' "$out" | grep -q '^llvm-tools' || return 1
  printf 'rustfmt, clippy, llvm-tools on %s' "$ch"
}
check_rust_target() {
  command -v rustup >/dev/null 2>&1 || return 1
  rustup target list --installed --toolchain "$(project_channel)" 2>/dev/null | grep -qx 'aarch64-apple-darwin' \
    && printf 'aarch64-apple-darwin'
}
check_brew() { command -v brew >/dev/null 2>&1 && brew --version 2>/dev/null | head -1; }
check_cargo_sub() {   # check_cargo_sub <subcommand>
  command -v "cargo-$1" >/dev/null 2>&1 || return 1
  local v; v=$(cargo +stable "$1" --version 2>/dev/null | head -1)
  printf '%s' "${v:-installed}"
}
check_bin() { command -v "$1" 2>/dev/null; }

check_component() {
  case "$1" in
    clt) check_clt ;;
    rustup) check_rustup ;;
    toolchain) check_toolchain ;;
    rust-components) check_rust_components ;;
    rust-target) check_rust_target ;;
    brew) check_brew ;;
    cargo-nextest) check_cargo_sub nextest ;;
    cargo-llvm-cov) check_cargo_sub llvm-cov ;;
    cargo-mutants) check_cargo_sub mutants ;;
    cargo-deny) check_cargo_sub deny ;;
    cargo-audit) check_cargo_sub audit ;;
    cargo-fuzz) check_cargo_sub fuzz ;;
    cargo-cyclonedx) check_cargo_sub cyclonedx ;;
    shellcheck|actionlint|just|hyperfine|tart) check_bin "$1" ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------- per-component installers
# Return 0 on success, 2 if skipped for lack of consent, anything else = failure.

install_clt() {
  say "Triggering Apple's Command Line Tools installer. A macOS dialog will appear; accept it."
  run_tty xcode-select --install   # non-zero if a request is already pending; we poll regardless
  [ "$DRY_RUN" = 1 ] && return 0
  local waited=0
  until check_clt >/dev/null 2>&1; do
    if [ "$waited" -ge "$CLT_WAIT" ]; then
      say "Timed out after ${CLT_WAIT}s waiting for the Command Line Tools install."
      return 1
    fi
    sleep 10; waited=$((waited + 10))
  done
}

install_rustup() {
  local base=https://static.rust-lang.org/rustup/dist/aarch64-apple-darwin
  remote_consent "rustup-init" "$base/rustup-init" || { say "rustup install not authorized (use --allow-remote-installers); skipping."; return 2; }
  if [ "$DRY_RUN" = 1 ]; then
    say "would download $base/rustup-init + .sha256, verify, then run: rustup-init -y --default-toolchain none --profile minimal$([ "$MODIFY_PATH" = 1 ] || echo ' --no-modify-path')"
    return 0
  fi
  fetch "$base/rustup-init" "$TMP_DIR/rustup-init" || return 1
  fetch "$base/rustup-init.sha256" "$TMP_DIR/rustup-init.sha256" || return 1
  local expected actual
  expected=$(awk 'NR==1 {print $1}' "$TMP_DIR/rustup-init.sha256")
  actual=$(sha256 "$TMP_DIR/rustup-init")
  # Fail closed: an empty or mismatching checksum never reaches execution.
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    say "rustup-init checksum mismatch (expected '$expected', got '$actual'); refusing to run it."
    return 1
  fi
  say "rustup-init sha256 verified: $actual"
  chmod 700 "$TMP_DIR/rustup-init"
  if [ "$MODIFY_PATH" = 1 ]; then
    run "$TMP_DIR/rustup-init" -y --default-toolchain none --profile minimal
  else
    run "$TMP_DIR/rustup-init" -y --default-toolchain none --profile minimal --no-modify-path
  fi
}

install_toolchain() {
  local ch; ch=$(project_channel)
  if [ -f "$REPO_ROOT/rust-toolchain.toml" ]; then
    # With no arguments, rustup installs what rust-toolchain.toml describes (components/targets too).
    (cd "$REPO_ROOT" && run rustup toolchain install)
    # Fallback for rustup versions that do not support the no-argument form.
    rustup toolchain list 2>/dev/null | grep -q "^$ch" || [ "$DRY_RUN" = 1 ] || run rustup toolchain install "$ch" --profile minimal || return 1
  else
    run rustup toolchain install "$ch" --profile minimal || return 1
  fi
  # 'stable' is used to build cargo tools so a pinned/old project toolchain cannot break them.
  if [ "$ch" != stable ] && ! rustup toolchain list 2>/dev/null | grep -q '^stable'; then
    run rustup toolchain install stable --profile minimal || return 1
  fi
  # Give the user a default only if they have none (we install with --default-toolchain none).
  if ! rustup toolchain list 2>/dev/null | grep -q 'default'; then
    run rustup default stable || return 1
  fi
}
install_rust_components() { run rustup component add rustfmt clippy llvm-tools-preview --toolchain "$(project_channel)"; }
install_rust_target() { run rustup target add aarch64-apple-darwin --toolchain "$(project_channel)"; }

install_brew() {
  local url=https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh
  local f="$TMP_DIR/homebrew-install.sh"
  remote_consent "Homebrew" "$url" || { say "Homebrew install not authorized (use --allow-remote-installers); skipping."; return 2; }
  if [ "$DRY_RUN" = 1 ]; then say "would download $url and run it with /bin/bash"; return 0; fi
  fetch "$url" "$f" || return 1
  say "Saved installer to $f (sha256 $(sha256 "$f"))"
  if [ "$INTERACTIVE" = 1 ] && [ "$ALLOW_REMOTE" != 1 ]; then
    ASSUME_YES_SAVED=$ASSUME_YES; ASSUME_YES=0
    if confirm "View the script before running it?" n; then "${PAGER:-less}" "$f"; fi
    confirm "Run it now?" y; local rc=$?
    ASSUME_YES=$ASSUME_YES_SAVED
    [ $rc -eq 0 ] || return 2
    run_tty /bin/bash "$f"          # attached to the terminal so it can ask for your password
  else
    # Unattended: Homebrew needs passwordless sudo here; if not available it fails and we report it.
    run env NONINTERACTIVE=1 /bin/bash "$f"
  fi
}

install_cargo_tool() { (cd "$TMP_DIR" && run cargo +stable install --locked "$1"); }
install_brew_formula() {
  local formula="$1"
  [ "$1" = tart ] && formula="cirruslabs/cli/tart"
  run env HOMEBREW_NO_ENV_HINTS=1 brew install "$formula"
}

install_component() {
  case "$1" in
    clt) install_clt ;;
    rustup) install_rustup ;;
    toolchain) install_toolchain ;;
    rust-components) install_rust_components ;;
    rust-target) install_rust_target ;;
    brew) install_brew ;;
    cargo-*) install_cargo_tool "$1" ;;
    shellcheck|actionlint|just|hyperfine|tart) install_brew_formula "$1" ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------- summary / exit
finish() {
  local id tier deps desc st detail rc=0 shown_any=0
  say ""
  say "Summary"
  say "-------"
  while IFS='|' read -r id tier deps desc <&4; do
    [ -z "$id" ] && continue
    st=$(status_of "$id"); [ -z "$st" ] && continue
    detail=$(printf '%s' "$RESULTS" | grep "^$id|" | tail -1 | cut -d'|' -f3-)
    shown_any=1
    local color="$C_OFF"
    case "$st" in
      present|installed) color="$C_GRN" ;;
      missing|failed|blocked) color="$C_RED" ;;
      skipped|would-install) color="$C_YEL" ;;
    esac
    printf '%-16s %-14s %s%-13s%s %s\n' "$id" "($tier)" "$color" "$st" "$C_OFF" "$detail"
    log_line "result: $id ($tier) $st $detail"
    if ! is_satisfied "$st" && [ "$st" != "would-install" ]; then
      case "$tier" in
        required) rc=1 ;;
        recommended) [ $rc -eq 0 ] && rc=4 ;;
        optional) case "$st" in failed|blocked) [ $rc -eq 0 ] && rc=4 ;; esac ;;
      esac
    fi
  done 4<<EOF
$COMPONENTS
EOF
  [ "$shown_any" = 0 ] && say "(nothing processed)"
  [ "${ABORTED:-0}" = 1 ] && [ $rc -eq 0 ] && rc=4

  say ""
  if [ "$CARGO_ON_PATH" = 0 ] && [ -x "$HOME/.cargo/bin/rustup" ] && [ "$MODIFY_PATH" = 0 ]; then
    say "Note: ~/.cargo/bin is not on your shell's PATH. Add this to your profile (e.g. ~/.zprofile):"
    say "    . \"\$HOME/.cargo/env\""
  fi
  [ -n "$LOG_FILE" ] && say "Log: $LOG_FILE"
  case $rc in
    0) say "Result: OK" ;;
    1) say "Result: a REQUIRED component is missing or failed. Re-run without --check, or see the log." ;;
    4) if [ "${ABORTED:-0}" = 1 ]; then
         say "Result: aborted by user; remaining components were not processed."
       else
         say "Result: partial. Required tools are fine, but recommended/optional ones are missing, skipped, or failed."
       fi ;;
  esac
  exit $rc
}

# ---------------------------------------------------------------- platform gate
ABORTED=0
say "bootstrap.sh $BOOTSTRAP_VERSION  repo: $REPO_ROOT"
[ -n "$FORCED_CHECK_REASON" ] && say "Note: $FORCED_CHECK_REASON"
log_line "mode=$MODE dry_run=$DRY_RUN yes=$ASSUME_YES interactive=$INTERACTIVE allow_remote=$ALLOW_REMOTE"

if [ "$ALLOW_UNSUPPORTED" != 1 ]; then
  [ "$(uname -s)" = Darwin ] || die "this script supports macOS only (use --allow-unsupported to override)" 3
  [ "$(uname -m)" = arm64 ] || die "Apple Silicon (arm64) required; got $(uname -m) (use --allow-unsupported to override)" 3
  # Under Rosetta uname reports x86_64 and the wrong (Intel) toolchain would be installed; the
  # explicit check below also catches shells that report arm64 but whose parent is translated.
  [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ] && die "running under Rosetta; open a native arm64 terminal" 3
fi
macos_ver=$(sw_vers -productVersion 2>/dev/null || echo unknown)
say "Host: macOS $macos_ver, $(uname -m)"
case "${macos_ver%%.*}" in ''|*[!0-9]*) : ;; *) [ "${macos_ver%%.*}" -lt 13 ] && warn "macOS $macos_ver is older than 13; untested" ;; esac

# Remember whether ~/.cargo/bin was on the caller's PATH; load_env adds it for this script only.
case ":$PATH:" in *":$HOME/.cargo/bin:"*) CARGO_ON_PATH=1 ;; *) CARGO_ON_PATH=0 ;; esac
load_env

# ---------------------------------------------------------------- main loop
# fd 3 feeds the component list so prompts inside the loop can read the real stdin.
while IFS='|' read -r id tier deps desc <&3; do
  [ -z "$id" ] && continue
  [ -n "$ONLY" ] && ! in_list "$id" "$ONLY" && continue
  [ -n "$SKIP" ] && in_list "$id" "$SKIP" && continue
  [ "$REQUIRED_ONLY" = 1 ] && [ "$tier" != required ] && continue

  say ""
  say "[$tier] $id – $desc"

  # Dependency gate: a dependency counts if it was just satisfied, or is simply present on disk.
  if [ "$deps" != "-" ]; then
    dst=$(status_of "$deps")
    if [ -z "$dst" ]; then check_component "$deps" >/dev/null 2>&1 && dst=present; fi
    if [ "$DRY_RUN" = 1 ] && [ "$dst" = would-install ]; then dst=present; fi
    if ! is_satisfied "$dst"; then
      say "  blocked: needs '$deps' first"
      set_status "$id" blocked "needs $deps"
      continue
    fi
  fi

  if detail=$(check_component "$id" 2>/dev/null); then
    say "  ${C_GRN}present${C_OFF} ${detail}"
    set_status "$id" present "$detail"
    continue
  fi
  say "  not found"

  if [ "$MODE" = check ]; then set_status "$id" missing "$([ -n "$FORCED_CHECK_REASON" ] && echo 'run with --yes to install' || echo 'check only')"; continue; fi

  # Optional tools are never installed unattended unless asked for.
  if [ "$tier" = optional ] && [ "$ASSUME_YES" = 1 ] && [ "$WITH_OPTIONAL" != 1 ]; then
    say "  skipped (optional; pass --with-optional to include)"
    set_status "$id" skipped "optional"
    continue
  fi
  default=y; [ "$tier" = optional ] && default=n
  if ! confirm "  Install $id?" "$default"; then
    say "  skipped"
    set_status "$id" skipped "declined"
    continue
  fi

  install_component "$id"; rc=$?
  if [ "$DRY_RUN" = 1 ] && [ $rc -eq 0 ]; then
    set_status "$id" would-install "dry run"
    continue
  fi
  if [ $rc -eq 2 ]; then set_status "$id" skipped "no consent for remote installer"; continue; fi
  load_env
  if [ $rc -eq 0 ] && detail=$(check_component "$id" 2>/dev/null); then
    say "  ${C_GRN}installed${C_OFF} ${detail}"
    set_status "$id" installed "$detail"
  else
    say "  ${C_RED}failed${C_OFF} (see log)"
    set_status "$id" failed "install did not verify"
  fi
done 3<<EOF
$COMPONENTS
EOF

finish
