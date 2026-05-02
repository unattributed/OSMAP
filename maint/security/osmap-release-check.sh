#!/bin/sh

set -u

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

profile=${OSMAP_SECURITY_PROFILE:-release}
if [ "$profile" != "release" ]; then
	echo "error: osmap-release-check requires OSMAP_SECURITY_PROFILE=release" >&2
	exit 1
fi

: "${TMPDIR:=/tmp/osmap-tmp}"
: "${CARGO_HOME:=/tmp/osmap-cargo-home}"
: "${CARGO_TARGET_DIR:=/tmp/osmap-target}"
: "${OSMAP_RELEASE_EVIDENCE_DIR:=$repo_root/maint/live}"
: "${OSMAP_RELEASE_RUSTC_VERSION:=1.86.0}"
: "${OSMAP_RELEASE_CARGO_VERSION:=1.86.0}"
: "${OSMAP_RELEASE_CLIPPY_VERSION:=0.1.86}"
: "${OSMAP_RELEASE_RUSTFMT_VERSION:=1.8.0-stable}"
: "${OSMAP_CARGO_DENY_VERSION:=0.18.3}"
: "${OSMAP_CARGO_AUDIT_VERSION:=0.22.1}"
: "${OSMAP_RELEASE_HOST_TARGET:=mail.blackbagsecurity.com}"
: "${OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-v3-dependency-inventory.txt}"
: "${OSMAP_RELEASE_SUMMARY_JSON:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-v3-release-evidence-summary.json}"
: "${OSMAP_RELEASE_SUMMARY_MD:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-v3-release-evidence-summary.md}"
: "${OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-v3-release-evidence.tar.gz}"
: "${OSMAP_RELEASE_WSTG_SUMMARY_PATH:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-wstg-release-summary.json}"
: "${OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE:=maint/live/latest-host-v2-readiness-report.txt maint/live/latest-host-v2-readiness-service-guard-report.txt docs/V2_PILOT_STATUS.md docs/V2_PILOT_CLOSEOUT.md}"
: "${OSMAP_RELEASE_HOST_READINESS_EVIDENCE:=maint/live/latest-host-v2-readiness-report.txt maint/live/latest-host-edge-cutover-report.txt maint/live/latest-host-internet-exposure-report.txt maint/live/latest-host-service-enablement-report.txt}"
: "${OSMAP_RELEASE_TLS_EDGE_EVIDENCE:=maint/live/osmap-v3-tls-cbc-cleanup-evidence-2026-05-02.txt}"
: "${OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND:=sh maint/security/osmap-supply-chain-check.sh}"

mkdir -p "$TMPDIR" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$OSMAP_RELEASE_EVIDENCE_DIR"
export TMPDIR CARGO_HOME CARGO_TARGET_DIR

assessed_ref=${OSMAP_RELEASE_ASSESSED_REF:-$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')}
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
command_line="make release-check"
if [ "$#" -gt 0 ]; then
	command_line="$command_line $*"
fi

failures=0
skipped_checks=""
cargo_build_result="not_run"
cargo_test_result="not_run"
cargo_clippy_result="not_run"
cargo_fmt_result="not_run"
supply_chain_result="not_run"
dependency_inventory_result="missing"
wstg_result="missing"
authenticated_wstg_status="missing"
sanitized_archive_status="missing"
v2_checked=""
host_checked=""
tls_checked=""
tls_cbc_status="missing"

add_skip() {
	if [ -z "$skipped_checks" ]; then
		skipped_checks=$1
	else
		skipped_checks="${skipped_checks}
$1"
	fi
}

fail() {
	echo "error: $*" >&2
	failures=$((failures + 1))
}

require_command() {
	name=$1
	if ! command -v "$name" >/dev/null 2>&1; then
		add_skip "missing required command: $name"
		fail "missing required command: $name"
		return 1
	fi
	return 0
}

check_exact_version() {
	label=$1
	actual=$2
	required=$3
	if [ "$actual" != "$required" ]; then
		add_skip "$label version mismatch: required $required, found $actual"
		fail "$label version mismatch: required $required, found $actual"
		return 1
	fi
	return 0
}

run_phase() {
	label=$1
	shift
	echo "==> $*"
	if "$@"; then
		eval "${label}_result=passed"
		return 0
	fi
	eval "${label}_result=failed"
	fail "$label failed"
	return 1
}

check_path_list() {
	label=$1
	paths=$2
	checked=""
	for path in $paths; do
		if [ ! -s "$path" ]; then
			add_skip "missing $label evidence: $path"
			fail "missing $label evidence: $path"
		else
			if [ -z "$checked" ]; then
				checked=$path
			else
				checked="${checked}
$path"
			fi
		fi
	done
	printf '%s' "$checked"
}

json_array() {
	if [ -z "$1" ]; then
		printf '[]'
		return
	fi
	printf '%s\n' "$1" | python3 -c 'import json,sys; print(json.dumps([line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]))'
}

json_string() {
	printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

write_summary() {
	skips_json=$(json_array "$skipped_checks")
	v2_json=$(json_array "$v2_checked")
	host_json=$(json_array "$host_checked")
	tls_json=$(json_array "$tls_checked")
	cat > "$OSMAP_RELEASE_SUMMARY_JSON" <<EOF
{
  "assessed_ref": $(json_string "$assessed_ref"),
  "generated_at_utc": $(json_string "$timestamp"),
  "host_target": $(json_string "$OSMAP_RELEASE_HOST_TARGET"),
  "command_line": $(json_string "$command_line"),
  "security_profile": "release",
  "cargo": {
    "build": $(json_string "$cargo_build_result"),
    "test": $(json_string "$cargo_test_result"),
    "clippy": $(json_string "$cargo_clippy_result"),
    "fmt_check": $(json_string "$cargo_fmt_result")
  },
  "supply_chain": $(json_string "$supply_chain_result"),
  "dependency_inventory_path": $(json_string "$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH"),
  "dependency_inventory_status": $(json_string "$dependency_inventory_result"),
  "wstg_summary_path": $(json_string "$OSMAP_RELEASE_WSTG_SUMMARY_PATH"),
  "wstg_status": $(json_string "$wstg_result"),
  "authenticated_wstg_status": $(json_string "$authenticated_wstg_status"),
  "v2_carry_forward_evidence_files_checked": $v2_json,
  "host_readiness_evidence_files_checked": $host_json,
  "tls_cbc_status": $(json_string "$tls_cbc_status"),
  "tls_edge_evidence_files_checked": $tls_json,
  "skipped_checks": $skips_json,
  "sanitized_evidence_archive_path": $(json_string "$OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH"),
  "sanitized_evidence_archive_status": $(json_string "$sanitized_archive_status")
}
EOF

	cat > "$OSMAP_RELEASE_SUMMARY_MD" <<EOF
# OSMAP V3 Release Evidence Summary

- Assessed ref: \`$assessed_ref\`
- Generated UTC: \`$timestamp\`
- Host target: \`$OSMAP_RELEASE_HOST_TARGET\`
- Command: \`$command_line\`
- Cargo build: \`$cargo_build_result\`
- Cargo test: \`$cargo_test_result\`
- Cargo clippy: \`$cargo_clippy_result\`
- Cargo fmt-check: \`$cargo_fmt_result\`
- Supply-chain: \`$supply_chain_result\`
- Dependency inventory: \`$dependency_inventory_result\` at \`$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH\`
- WSTG summary: \`$wstg_result\` at \`$OSMAP_RELEASE_WSTG_SUMMARY_PATH\`
- Authenticated WSTG: \`$authenticated_wstg_status\`
- TLS CBC cleanup: \`$tls_cbc_status\`
- Sanitized evidence archive: \`$sanitized_archive_status\` at \`$OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH\`
- Skipped checks: \`$(printf '%s' "$skipped_checks" | tr '\n' '; ')\`

## V2 Carry-Forward Evidence

$(printf '%s\n' "$v2_checked" | sed '/^$/d; s/^/- `/' | sed 's/$/`/')

## Host-Readiness Evidence

$(printf '%s\n' "$host_checked" | sed '/^$/d; s/^/- `/' | sed 's/$/`/')

## TLS Edge Evidence

$(printf '%s\n' "$tls_checked" | sed '/^$/d; s/^/- `/' | sed 's/$/`/')
EOF
}

validate_wstg_summary() {
	if [ ! -s "$OSMAP_RELEASE_WSTG_SUMMARY_PATH" ]; then
		add_skip "missing WSTG release summary: $OSMAP_RELEASE_WSTG_SUMMARY_PATH"
		fail "missing WSTG release summary: $OSMAP_RELEASE_WSTG_SUMMARY_PATH"
		return 1
	fi
	if python3 - "$OSMAP_RELEASE_WSTG_SUMMARY_PATH" "$repo_root/maint/wstg-testing-pack/wstg-asvs-mapping.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
mapping = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
results = {item.get("test_id"): item for item in summary.get("results", [])}
errors = []
auth_required = []

for item in mapping.get("tests", []):
    test_id = item["test_id"]
    release_required = item.get("release_required") is True
    auth_required_flag = item.get("requires_authenticated_coverage") is True
    if auth_required_flag:
        auth_required.append(test_id)
    if not release_required:
        continue
    result = results.get(test_id)
    if result is None:
        errors.append(f"{test_id} missing from WSTG release summary")
        continue
    status = result.get("status")
    if status != "pass":
        errors.append(f"{test_id} has release-blocking status {status}")
    if auth_required_flag and status == "skip":
        errors.append(f"{test_id} skipped authenticated coverage")
    if auth_required_flag and not item.get("requires_totp"):
        errors.append(f"{test_id} requires authenticated coverage but does not require TOTP")

proof = summary.get("authenticated_proof", {})
proof_required = ["login", "totp", "session_issued", "protected_route_access", "logout", "session_invalidated"]
for key in proof_required:
    if proof.get(key) is not True:
        errors.append(f"authenticated proof missing {key}")

if summary.get("release_mode") is not True:
    errors.append("WSTG summary was not produced in release mode")
if summary.get("counts", {}).get("skip", 0) != 0:
    errors.append("WSTG release summary contains skipped tests")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
print("authenticated_wstg_status=passed")
PY
	then
		wstg_result="passed"
		authenticated_wstg_status="passed"
		return 0
	fi
	wstg_result="failed"
	authenticated_wstg_status="failed"
	fail "WSTG release summary did not satisfy release mode"
	return 1
}

echo "==> validating pinned release toolchain"
require_command python3 >/dev/null || true
require_command cargo >/dev/null || true
require_command rustc >/dev/null || true
require_command tar >/dev/null || true

if command -v rustc >/dev/null 2>&1; then
	check_exact_version rustc "$(rustc --version | awk '{ print $2 }')" "$OSMAP_RELEASE_RUSTC_VERSION" || true
fi
if command -v cargo >/dev/null 2>&1; then
	check_exact_version cargo "$(cargo --version | awk '{ print $2 }')" "$OSMAP_RELEASE_CARGO_VERSION" || true
	if cargo clippy --version >/dev/null 2>&1; then
		check_exact_version clippy "$(cargo clippy --version | awk '{ print $2 }')" "$OSMAP_RELEASE_CLIPPY_VERSION" || true
	else
		add_skip "missing required cargo subcommand: clippy"
		fail "missing required cargo subcommand: clippy"
	fi
	if cargo fmt --version >/dev/null 2>&1; then
		check_exact_version rustfmt "$(cargo fmt --version | awk '{ print $2 }')" "$OSMAP_RELEASE_RUSTFMT_VERSION" || true
	else
		add_skip "missing required cargo subcommand: fmt"
		fail "missing required cargo subcommand: fmt"
	fi
	if cargo audit --version >/dev/null 2>&1; then
		check_exact_version cargo-audit "$(cargo audit --version | awk '{ print $2 }')" "$OSMAP_CARGO_AUDIT_VERSION" || true
	else
		add_skip "missing required cargo subcommand: audit"
		fail "missing required cargo subcommand: audit"
	fi
	if cargo deny --version >/dev/null 2>&1; then
		check_exact_version cargo-deny "$(cargo deny --version | awk '{ print $2 }')" "$OSMAP_CARGO_DENY_VERSION" || true
	else
		add_skip "missing required cargo subcommand: deny"
		fail "missing required cargo subcommand: deny"
	fi
fi

if [ "$failures" -eq 0 ]; then
	run_phase cargo_build cargo build --locked --all-features || true
	run_phase cargo_test cargo test --locked --all-features || true
	run_phase cargo_clippy cargo clippy --locked --all-targets --all-features -- -D warnings || true
	run_phase cargo_fmt cargo fmt --check || true

	echo "==> supply-chain gate"
	if sh -c "$OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND"; then
		supply_chain_result="passed"
	else
		supply_chain_result="failed"
		fail "supply-chain gate failed"
	fi

	echo "==> dependency inventory"
	if cargo tree --locked --all-features --color never > "$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH.tmp"; then
		mv "$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH.tmp" "$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH"
		if [ -s "$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH" ]; then
			dependency_inventory_result="passed"
		else
			dependency_inventory_result="missing"
			add_skip "dependency inventory is empty: $OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH"
			fail "dependency inventory is empty"
		fi
	else
		rm -f "$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH.tmp"
		dependency_inventory_result="failed"
		add_skip "dependency inventory generation failed"
		fail "dependency inventory generation failed"
	fi
else
	add_skip "cargo validation skipped because release toolchain preflight failed"
	add_skip "supply-chain validation skipped because release toolchain preflight failed"
	add_skip "dependency inventory skipped because release toolchain preflight failed"
fi

echo "==> validating required release evidence"
v2_checked=$(check_path_list "V2 carry-forward" "$OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE")
host_checked=$(check_path_list "host-readiness" "$OSMAP_RELEASE_HOST_READINESS_EVIDENCE")
tls_failures_before=$failures
tls_checked=$(check_path_list "TLS edge" "$OSMAP_RELEASE_TLS_EDGE_EVIDENCE")
if [ -n "$tls_checked" ] && [ "$failures" -eq "$tls_failures_before" ]; then
	tls_cbc_status="passed"
else
	tls_cbc_status="missing"
fi
validate_wstg_summary || true

if [ "$failures" -eq 0 ]; then
	echo "==> writing sanitized release evidence archive"
	sanitized_archive_status="creating"
	write_summary
	if tar -czf "$OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH" \
		"$OSMAP_RELEASE_SUMMARY_JSON" \
		"$OSMAP_RELEASE_SUMMARY_MD" \
		"$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH" \
		$OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE \
		$OSMAP_RELEASE_HOST_READINESS_EVIDENCE \
		$OSMAP_RELEASE_TLS_EDGE_EVIDENCE \
		"$OSMAP_RELEASE_WSTG_SUMMARY_PATH"; then
		sanitized_archive_status="passed"
		write_summary
		if ! tar -czf "$OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH" \
			"$OSMAP_RELEASE_SUMMARY_JSON" \
			"$OSMAP_RELEASE_SUMMARY_MD" \
			"$OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH" \
			$OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE \
			$OSMAP_RELEASE_HOST_READINESS_EVIDENCE \
			$OSMAP_RELEASE_TLS_EDGE_EVIDENCE \
			"$OSMAP_RELEASE_WSTG_SUMMARY_PATH"; then
			sanitized_archive_status="failed"
			fail "sanitized evidence archive generation failed after final summary"
		fi
	else
		sanitized_archive_status="failed"
		fail "sanitized evidence archive generation failed"
	fi
else
	sanitized_archive_status="not_created"
fi

write_summary

if [ "$failures" -ne 0 ] || [ -n "$skipped_checks" ]; then
	echo "error: release-check failed; see $OSMAP_RELEASE_SUMMARY_JSON" >&2
	exit 1
fi

echo "==> release-check complete"
