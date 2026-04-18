#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

: "${TMPDIR:=/tmp/osmap-tmp}"
: "${CARGO_HOME:=/tmp/osmap-cargo-home}"
: "${CARGO_TARGET_DIR:=/tmp/osmap-target}"

mkdir -p "$TMPDIR" "$CARGO_HOME" "$CARGO_TARGET_DIR"
export TMPDIR CARGO_HOME CARGO_TARGET_DIR

version_lt() {
	left=$1
	right=$2

	old_ifs=$IFS
	IFS=.
	set -- $left
	IFS=$old_ifs
	left_major=${1:-0}
	left_minor=${2:-0}
	left_patch=${3:-0}

	IFS=.
	set -- $right
	IFS=$old_ifs
	right_major=${1:-0}
	right_minor=${2:-0}
	right_patch=${3:-0}

	if [ "$left_major" -lt "$right_major" ]; then
		return 0
	fi
	if [ "$left_major" -gt "$right_major" ]; then
		return 1
	fi
	if [ "$left_minor" -lt "$right_minor" ]; then
		return 0
	fi
	if [ "$left_minor" -gt "$right_minor" ]; then
		return 1
	fi
	if [ "$left_patch" -lt "$right_patch" ]; then
		return 0
	fi
	return 1
}

required_rust_version=$(awk -F'"' '/^rust-version[[:space:]]*=/ { print $2; exit }' Cargo.toml)
run_cargo_phases=1

if ! command -v cargo >/dev/null 2>&1; then
	echo "note: cargo is not installed in this environment; skipping cargo-based security-check phases"
	run_cargo_phases=0
else
	current_rust_version=$(rustc --version 2>/dev/null | awk '{ print $2 }' || true)
	if [ -z "$current_rust_version" ]; then
		echo "note: rustc is not available in this environment; skipping cargo-based security-check phases"
		run_cargo_phases=0
	elif [ -n "$required_rust_version" ] && version_lt "$current_rust_version" "$required_rust_version"; then
		echo "note: rustc $current_rust_version is older than the repo minimum $required_rust_version; skipping cargo-based security-check phases in this environment"
		echo "note: run the full gate in CI or on a compatible host such as mail.blackbagsecurity.com"
		run_cargo_phases=0
	fi
fi

if [ "$run_cargo_phases" -eq 1 ]; then
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
fi

echo "==> scanning for disallowed unsafe outside src/openbsd.rs"
unsafe_hits=$(grep -RInE 'unsafe[[:space:]]*(fn|impl|trait|\{)' src 2>/dev/null || true)
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

echo "==> validating closeout ssh wrapper command assembly"
sh maint/security/test-osmap-run-v1-closeout-over-ssh.sh

echo "==> validating local closeout wrapper step and report handling"
sh maint/security/test-osmap-live-validate-v1-closeout.sh

echo "==> validating local v2 readiness wrapper step and report handling"
sh maint/security/test-osmap-live-validate-v2-readiness.sh

echo "==> validating reversible validation-password override flow"
sh maint/security/test-osmap-validation-password-override.sh

echo "==> validating V2 reversible validation-password override flow"
sh maint/security/test-osmap-v2-validation-password-override.sh

echo "==> validating hook installation and security gate invocation"
sh maint/security/test-osmap-install-hooks.sh

echo "==> validating v2 readiness ssh wrapper command assembly"
sh maint/security/test-osmap-run-v2-readiness-over-ssh.sh

echo "==> validating internet exposure assessment wrapper behavior"
sh maint/security/test-osmap-live-assess-internet-exposure.sh

echo "==> validating edge cutover wrapper behavior"
sh maint/security/test-osmap-live-validate-edge-cutover.sh

echo "==> validating reviewed mail host edge artifacts"
sh maint/security/test-osmap-mail-host-edge-artifacts.sh

echo "==> validating edge cutover rehearsal wrapper behavior"
sh maint/security/test-osmap-live-rehearse-edge-cutover.sh

echo "==> validating service enablement rehearsal wrapper behavior"
sh maint/security/test-osmap-live-rehearse-service-enablement.sh

echo "==> validating service enablement wrapper behavior"
sh maint/security/test-osmap-live-validate-service-enablement.sh

echo "==> validating binary deployment rehearsal wrapper behavior"
sh maint/security/test-osmap-live-rehearse-binary-deployment.sh

echo "==> validating runtime-group provisioning rehearsal wrapper behavior"
sh maint/security/test-osmap-live-rehearse-runtime-group-provisioning.sh

echo "==> validating service-artifact rehearsal wrapper behavior"
sh maint/security/test-osmap-live-rehearse-service-artifacts.sh

echo "==> security-check complete"
