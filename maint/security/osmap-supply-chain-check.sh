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

cargo_audit_bin() {
	if command -v cargo-audit >/dev/null 2>&1; then
		command -v cargo-audit
	elif [ -x "${HOME}/.cargo/bin/cargo-audit" ]; then
		printf '%s\n' "${HOME}/.cargo/bin/cargo-audit"
	fi
}

cargo_deny_bin() {
	if command -v cargo-deny >/dev/null 2>&1; then
		command -v cargo-deny
	elif [ -x "${HOME}/.cargo/bin/cargo-deny" ]; then
		printf '%s\n' "${HOME}/.cargo/bin/cargo-deny"
	fi
}

cargo_audit_version() {
	bin=$(cargo_audit_bin || true)
	if [ -n "$bin" ]; then
		"$bin" --version
	else
		cargo audit --version
	fi
}

cargo_audit_check() {
	bin=$(cargo_audit_bin || true)
	if [ -n "$bin" ]; then
		"$bin" audit "$@"
	else
		cargo audit "$@"
	fi
}

cargo_deny() {
	bin=$(cargo_deny_bin || true)
	if [ -n "$bin" ]; then
		"$bin" "$@"
	else
		cargo deny "$@"
	fi
}

if ! cargo_deny --version >/dev/null 2>&1; then
	if [ "$OSMAP_BOOTSTRAP_CARGO_DENY" = "1" ]; then
		echo "==> installing cargo-deny ${OSMAP_CARGO_DENY_VERSION}"
		cargo install cargo-deny --version "$OSMAP_CARGO_DENY_VERSION" --locked
		PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:$PATH"
	else
		echo "error: cargo-deny is required for the supply-chain gate" >&2
		echo "hint: install cargo-deny ${OSMAP_CARGO_DENY_VERSION}, or set OSMAP_BOOTSTRAP_CARGO_DENY=1 for a controlled bootstrap" >&2
		exit 1
	fi
fi

if ! cargo_audit_version >/dev/null 2>&1; then
	if [ "$OSMAP_BOOTSTRAP_CARGO_AUDIT" = "1" ]; then
		echo "==> installing cargo-audit ${OSMAP_CARGO_AUDIT_VERSION}"
		cargo install cargo-audit --version "$OSMAP_CARGO_AUDIT_VERSION" --locked
		PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:$PATH"
	else
		echo "error: cargo-audit is required for the supply-chain advisory gate" >&2
		echo "hint: install cargo-audit ${OSMAP_CARGO_AUDIT_VERSION}, or set OSMAP_BOOTSTRAP_CARGO_AUDIT=1 for a controlled bootstrap" >&2
		exit 1
	fi
fi

audit_version=$(cargo_audit_version | awk '{ print $2 }')
if [ "$audit_version" != "$OSMAP_CARGO_AUDIT_VERSION" ]; then
	echo "error: cargo-audit ${OSMAP_CARGO_AUDIT_VERSION} is required, found ${audit_version}" >&2
	exit 1
fi

deny_version=$(cargo_deny --version | awk '{ print $2 }')
if [ "$deny_version" != "$OSMAP_CARGO_DENY_VERSION" ]; then
	echo "error: cargo-deny ${OSMAP_CARGO_DENY_VERSION} is required, found ${deny_version}" >&2
	exit 1
fi

echo "==> risk-based direct dependency admission"
python3 -B maint/security/osmap-v15-dependency-admission-gate.py \
    --repo "$repo_root" \
    --record maint/security/v15-dependency-admission.json

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
	cargo_audit_check --deny warnings --db "$OSMAP_RUSTSEC_ADVISORY_DB_PATH" --no-fetch
else
	cargo_audit_check --deny warnings
fi

echo "==> cargo deny bans, licenses, and sources"
cargo_deny --locked check bans licenses sources

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
