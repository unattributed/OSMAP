#!/usr/bin/env bash

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf '%s\n' 'FAIL: execute this script with bash; do not source it.' >&2
    return 1
fi

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

REQUIRED_RUST="1.94.1"
REQUIRED_CARGO="1.94.1"
REQUIRED_CLIPPY="0.1.94"
REQUIRED_RUSTFMT="1.8.0"
REQUIRED_CARGO_AUDIT="0.22.1"
REQUIRED_CARGO_DENY="0.18.3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

[[ -n "$REPO_ROOT" && -f "$REPO_ROOT/Cargo.toml" ]] \
    || fail "run this verifier from an OSMAP repository checkout"

[[ -r /etc/os-release ]] || fail "/etc/os-release is unavailable"
# shellcheck disable=SC1091
source /etc/os-release

OS_FAMILY="${ID:-} ${ID_LIKE:-}"
case " $OS_FAMILY " in
    *" debian "*|*" parrot "*) ;;
    *)
        fail "unsupported operating-system family: ${PRETTY_NAME:-unknown}; Debian-family required"
        ;;
esac

export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export PATH="$CARGO_HOME/bin:$PATH"

for COMMAND in \
    bash cargo cargo-audit cargo-deny cc file git gpg grep gzip make \
    patch pkg-config python3 rustc rustup sed shellcheck ssh tar

do
    require_command "$COMMAND"
done

RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
CARGO_VERSION="$(cargo --version | awk '{print $2}')"
CLIPPY_VERSION="$(cargo clippy --version | awk '{print $2}')"
RUSTFMT_RAW="$(cargo fmt --version | awk '{print $2}')"
RUSTFMT_VERSION="${RUSTFMT_RAW%-stable}"
CARGO_AUDIT_VERSION="$(cargo-audit --version | awk '{print $2}')"
CARGO_DENY_VERSION="$(cargo-deny --version | awk '{print $2}')"
GPGME_VERSION="$(pkg-config --modversion gpgme)"
HOOKS_PATH="$(git -C "$REPO_ROOT" config --get core.hooksPath || true)"

[[ "$RUSTC_VERSION" == "$REQUIRED_RUST" ]] \
    || fail "rustc must be $REQUIRED_RUST; found $RUSTC_VERSION"
[[ "$CARGO_VERSION" == "$REQUIRED_CARGO" ]] \
    || fail "Cargo must be $REQUIRED_CARGO; found $CARGO_VERSION"
[[ "$CLIPPY_VERSION" == "$REQUIRED_CLIPPY" ]] \
    || fail "Clippy must be $REQUIRED_CLIPPY; found $CLIPPY_VERSION"
[[ "$RUSTFMT_VERSION" == "$REQUIRED_RUSTFMT" ]] \
    || fail "rustfmt must normalise to $REQUIRED_RUSTFMT; found $RUSTFMT_RAW"
[[ "$CARGO_AUDIT_VERSION" == "$REQUIRED_CARGO_AUDIT" ]] \
    || fail "cargo-audit must be $REQUIRED_CARGO_AUDIT; found $CARGO_AUDIT_VERSION"
[[ "$CARGO_DENY_VERSION" == "$REQUIRED_CARGO_DENY" ]] \
    || fail "cargo-deny must be $REQUIRED_CARGO_DENY; found $CARGO_DENY_VERSION"
[[ "$HOOKS_PATH" == ".githooks" ]] \
    || fail "repository hooks are not enabled; run make install-hooks"
[[ -x "$REPO_ROOT/.githooks/pre-commit" ]] \
    || fail ".githooks/pre-commit is not executable"
[[ -x "$REPO_ROOT/.githooks/pre-push" ]] \
    || fail ".githooks/pre-push is not executable"
[[ -x "$REPO_ROOT/.venv/bin/python" ]] \
    || fail "repository Python virtual environment is missing: $REPO_ROOT/.venv"

cargo metadata \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    --locked \
    --no-deps \
    --format-version 1 \
    >/dev/null

printf 'operating_system=%s\n' "${PRETTY_NAME:-unknown}"
printf 'rustc=%s\n' "$RUSTC_VERSION"
printf 'cargo=%s\n' "$CARGO_VERSION"
printf 'clippy=%s\n' "$CLIPPY_VERSION"
printf 'rustfmt_raw=%s\n' "$RUSTFMT_RAW"
printf 'rustfmt_normalised=%s\n' "$RUSTFMT_VERSION"
printf 'cargo_audit=%s\n' "$CARGO_AUDIT_VERSION"
printf 'cargo_deny=%s\n' "$CARGO_DENY_VERSION"
printf 'gpgme=%s\n' "$GPGME_VERSION"
printf 'python=%s\n' "$("$REPO_ROOT/.venv/bin/python" --version 2>&1)"
printf 'hooks_path=%s\n' "$HOOKS_PATH"
printf '%s\n' 'PASS: OSMAP Debian-family development environment is ready'
