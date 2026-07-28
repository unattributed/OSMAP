#!/usr/bin/env bash

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf '%s\n' 'FAIL: execute this script with bash; do not source it.' >&2
    return 1
fi

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

REQUIRED_RUST="1.94.1"
REQUIRED_CARGO_AUDIT="0.22.1"
REQUIRED_CARGO_DENY="0.18.3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"

usage() {
    cat <<'USAGE'
Usage: maint/development/bootstrap-debian.sh [--no-apt-update]

Install and configure the reviewed OSMAP development environment on a
Debian-family workstation, including Parrot OS.

Options:
  --no-apt-update  Do not refresh APT metadata before package installation.
  -h, --help       Show this help text.

Run this script as a normal user with sudo access. Do not run it as root and
do not source it.
USAGE
}

APT_UPDATE=1
while (($#)); do
    case "$1" in
        --no-apt-update) APT_UPDATE=0 ;;
        -h|--help) usage; exit 0 ;;
        *)
            printf 'FAIL: unsupported argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

if [[ "$(id -u)" -eq 0 ]]; then
    fail "run the bootstrap as a normal user, not as root"
fi

[[ -n "$REPO_ROOT" && -f "$REPO_ROOT/Cargo.toml" ]] \
    || fail "run this script from an OSMAP repository checkout"

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

for COMMAND in sudo apt-get apt-cache awk grep sed sort tee; do
    require_command "$COMMAND"
done

sudo -v

PACKAGES=(
    bash
    binutils
    ca-certificates
    coreutils
    curl
    dash
    diffutils
    file
    findutils
    g++
    gawk
    gcc
    git
    gnupg
    grep
    gzip
    jq
    libgpgme-dev
    libssl-dev
    make
    openssh-client
    patch
    pkg-config
    python3
    python3-venv
    rsync
    sed
    shellcheck
    tar
)

if ((APT_UPDATE)); then
    sudo apt-get update
fi

sudo apt-get install \
    --no-install-recommends \
    --yes \
    "${PACKAGES[@]}"

if ! command -v rustup >/dev/null 2>&1; then
    RUSTUP_CANDIDATE="$(
        apt-cache policy rustup |
            awk '/Candidate:/ {candidate=$2} END {print candidate}'
    )"

    [[ -n "$RUSTUP_CANDIDATE" && "$RUSTUP_CANDIDATE" != "(none)" ]] \
        || fail "the signed APT repositories do not provide a rustup candidate"

    SIMULATION="$(mktemp)"
    trap 'rm -f "$SIMULATION"' EXIT

    sudo apt-get \
        --simulate \
        install \
        --no-install-recommends \
        rustup |
        tee "$SIMULATION"

    mapfile -t REMOVALS < <(
        awk '$1 == "Remv" {print $2}' "$SIMULATION" |
            sort -u
    )

    for PACKAGE in "${REMOVALS[@]}"; do
        NORMALISED="${PACKAGE%%:*}"
        case "$NORMALISED" in
            cargo|rustc|rust-clippy|rustfmt|rust-src|rust-llvm|libstd-rust-*)
                printf 'Approved distribution Rust package replacement: %s\n' "$PACKAGE"
                ;;
            *)
                fail "rustup installation proposed an unrelated package removal: $PACKAGE"
                ;;
        esac
    done

    sudo apt-get install \
        --no-install-recommends \
        --yes \
        rustup

    rm -f "$SIMULATION"
    trap - EXIT
fi

export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_HTTP_MULTIPLEXING="${CARGO_HTTP_MULTIPLEXING:-false}"
export CARGO_NET_RETRY="${CARGO_NET_RETRY:-10}"

mkdir -p "$RUSTUP_HOME" "$CARGO_HOME/bin"
chmod 700 "$RUSTUP_HOME" "$CARGO_HOME" "$CARGO_HOME/bin"

add_profile_block() {
    local profile="$1"
    local marker="# OSMAP Rust and Cargo user environment"

    touch "$profile"
    if grep -Fq "$marker" "$profile"; then
        return 0
    fi

    cp -a "$profile" "${profile}.osmap-backup-$(date -u +%Y%m%dT%H%M%SZ)"

    cat >> "$profile" <<'PROFILE'

# OSMAP Rust and Cargo user environment
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
case ":$PATH:" in
    *":$CARGO_HOME/bin:"*) ;;
    *) export PATH="$CARGO_HOME/bin:$PATH" ;;
esac
PROFILE
}

add_profile_block "$HOME/.profile"
add_profile_block "$HOME/.bashrc"

rustup set profile minimal
rustup toolchain install \
    "$REQUIRED_RUST" \
    --profile minimal \
    --component clippy \
    --component rustfmt
rustup default "$REQUIRED_RUST"

install_cargo_tool() {
    local binary="$1"
    local crate="$2"
    local required="$3"
    local current=""

    if command -v "$binary" >/dev/null 2>&1; then
        current="$("$binary" --version | awk '{print $2}')"
    fi

    if [[ "$current" == "$required" ]]; then
        printf '%s %s is already installed\n' "$binary" "$required"
        return 0
    fi

    cargo +"$REQUIRED_RUST" install \
        "$crate" \
        --version "$required" \
        --locked \
        --force
}

install_cargo_tool cargo-audit cargo-audit "$REQUIRED_CARGO_AUDIT"
install_cargo_tool cargo-deny cargo-deny "$REQUIRED_CARGO_DENY"

if [[ ! -d "$REPO_ROOT/.venv" ]]; then
    python3 -m venv "$REPO_ROOT/.venv"
fi

git -C "$REPO_ROOT" config core.hooksPath .githooks
chmod +x \
    "$REPO_ROOT/.githooks/pre-commit" \
    "$REPO_ROOT/.githooks/pre-push"

"$REPO_ROOT/maint/development/verify-debian.sh"

printf '%s\n' \
    'PASS: the reviewed OSMAP Debian-family development environment is installed'
