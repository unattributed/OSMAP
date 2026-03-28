#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

: "${TMPDIR:=/tmp/osmap-tmp}"
: "${CARGO_HOME:=/tmp/osmap-cargo-home}"
: "${CARGO_TARGET_DIR:=/tmp/osmap-target}"

mkdir -p "$TMPDIR" "$CARGO_HOME" "$CARGO_TARGET_DIR"
export TMPDIR CARGO_HOME CARGO_TARGET_DIR

echo "==> cargo check"
cargo check

echo "==> cargo test"
cargo test

if cargo clippy --version >/dev/null 2>&1; then
	echo "==> cargo clippy --all-targets -- -D warnings"
	cargo clippy --all-targets -- -D warnings
else
	echo "note: cargo-clippy is not installed in this environment; skipping clippy phase"
fi

if cargo fmt --version >/dev/null 2>&1; then
	echo "==> cargo fmt --check"
	cargo fmt --check
else
	echo "note: rustfmt is not installed in this environment; skipping fmt-check phase"
fi

echo "==> scanning for disallowed unsafe outside src/openbsd.rs"
unsafe_hits=$(grep -RInE 'unsafe[[:space:]]|unsafe\{' src 2>/dev/null || true)
disallowed_unsafe=$(printf '%s\n' "$unsafe_hits" | grep -v 'src/openbsd.rs:' | sed '/^$/d' || true)
if [ -n "$disallowed_unsafe" ]; then
	echo "error: found unsafe outside the reviewed OpenBSD FFI boundary"
	printf '%s\n' "$disallowed_unsafe"
	exit 1
fi

echo "==> scanning for shell-based command execution"
shell_hits=$(grep -RIn '/bin/sh\|sh -c\|cmd /c\|powershell' src 2>/dev/null || true)
if [ -n "$shell_hits" ]; then
	echo "error: found shell-based command execution patterns in src/"
	printf '%s\n' "$shell_hits"
	exit 1
fi

echo "==> scanning for unexpected direct Command::new call sites"
command_hits=$(grep -RIn 'Command::new' src 2>/dev/null || true)
unexpected_command_hits=$(printf '%s\n' "$command_hits" | grep -v 'src/auth.rs:' | sed '/^$/d' || true)
if [ -n "$unexpected_command_hits" ]; then
	echo "error: found unreviewed direct Command::new call sites outside src/auth.rs"
	printf '%s\n' "$unexpected_command_hits"
	exit 1
fi

if [ -n "$command_hits" ]; then
	echo "note: reviewed direct command execution remains limited to:"
	printf '%s\n' "$command_hits"
fi

echo "==> security-check complete"
