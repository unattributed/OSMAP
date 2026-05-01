#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

: "${OSMAP_CARGO_DENY_VERSION:=0.18.3}"
: "${OSMAP_CARGO_AUDIT_VERSION:=0.22.1}"
: "${OSMAP_BOOTSTRAP_CARGO_DENY:=0}"
: "${OSMAP_BOOTSTRAP_CARGO_AUDIT:=0}"
: "${OSMAP_RUSTSEC_ADVISORY_DB_URL:=https://github.com/RustSec/advisory-db.git}"
: "${OSMAP_RUSTSEC_ADVISORY_DB_PATH:=${CARGO_HOME:-${HOME}/.cargo}/advisory-db}"

if ! command -v cargo >/dev/null 2>&1; then
	echo "error: cargo is required for the supply-chain gate" >&2
	exit 1
fi

if ! cargo deny --version >/dev/null 2>&1; then
	if [ "$OSMAP_BOOTSTRAP_CARGO_DENY" = "1" ]; then
		echo "==> installing cargo-deny ${OSMAP_CARGO_DENY_VERSION}"
		cargo install cargo-deny --version "$OSMAP_CARGO_DENY_VERSION" --locked
	else
		echo "error: cargo-deny is required for the supply-chain gate" >&2
		echo "hint: install cargo-deny ${OSMAP_CARGO_DENY_VERSION}, or set OSMAP_BOOTSTRAP_CARGO_DENY=1 for a controlled bootstrap" >&2
		exit 1
	fi
fi

if ! cargo audit --version >/dev/null 2>&1; then
	if [ "$OSMAP_BOOTSTRAP_CARGO_AUDIT" = "1" ]; then
		echo "==> installing cargo-audit ${OSMAP_CARGO_AUDIT_VERSION}"
		cargo install cargo-audit --version "$OSMAP_CARGO_AUDIT_VERSION" --locked
	else
		echo "error: cargo-audit is required for the supply-chain advisory gate" >&2
		echo "hint: install cargo-audit ${OSMAP_CARGO_AUDIT_VERSION}, or set OSMAP_BOOTSTRAP_CARGO_AUDIT=1 for a controlled bootstrap" >&2
		exit 1
	fi
fi

audit_version=$(cargo audit --version | awk '{ print $2 }')
if [ "$audit_version" != "$OSMAP_CARGO_AUDIT_VERSION" ]; then
	echo "error: cargo-audit ${OSMAP_CARGO_AUDIT_VERSION} is required, found ${audit_version}" >&2
	exit 1
fi

deny_version=$(cargo deny --version | awk '{ print $2 }')
if [ "$deny_version" != "$OSMAP_CARGO_DENY_VERSION" ]; then
	echo "error: cargo-deny ${OSMAP_CARGO_DENY_VERSION} is required, found ${deny_version}" >&2
	exit 1
fi

echo "==> cargo audit vulnerable and yanked advisories"
if command -v git >/dev/null 2>&1; then
	if [ -d "$OSMAP_RUSTSEC_ADVISORY_DB_PATH/.git" ]; then
		git -C "$OSMAP_RUSTSEC_ADVISORY_DB_PATH" fetch --depth 1 origin main
		git -C "$OSMAP_RUSTSEC_ADVISORY_DB_PATH" checkout -q FETCH_HEAD
	elif [ -e "$OSMAP_RUSTSEC_ADVISORY_DB_PATH" ]; then
		echo "error: advisory database path exists but is not a git checkout: ${OSMAP_RUSTSEC_ADVISORY_DB_PATH}" >&2
		exit 1
	else
		mkdir -p "$(dirname -- "$OSMAP_RUSTSEC_ADVISORY_DB_PATH")"
		git clone --depth 1 "$OSMAP_RUSTSEC_ADVISORY_DB_URL" "$OSMAP_RUSTSEC_ADVISORY_DB_PATH"
	fi
	cargo audit --deny warnings --db "$OSMAP_RUSTSEC_ADVISORY_DB_PATH" --no-fetch
else
	cargo audit --deny warnings
fi

echo "==> cargo deny bans, licenses, and sources"
cargo deny --locked check bans licenses sources

echo "==> cargo tree duplicate-version backstop"
duplicates=$(cargo tree -d --locked --color never 2>&1 || true)
if printf '%s\n' "$duplicates" | grep -Fq 'warning: nothing to print.'; then
	echo "no duplicate dependency versions found"
else
	echo "error: duplicate dependency versions were found" >&2
	printf '%s\n' "$duplicates" >&2
	exit 1
fi

echo "==> supply-chain check complete"
