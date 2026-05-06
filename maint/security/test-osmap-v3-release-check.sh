#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
release_check="${repo_root}/maint/security/osmap-release-check.sh"

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v3-release-check.XXXXXX")
cleanup() {
	rm -rf "$tmp_root"
}
trap cleanup EXIT

make_stubs() {
	stub_dir=$1
	mkdir -p "$stub_dir"
	cat > "$stub_dir/rustc" <<'EOF'
#!/bin/sh
printf '%s\n' 'rustc 1.86.0 (05f9846f8 2025-03-31)'
EOF
	cat > "$stub_dir/cargo" <<'EOF'
#!/bin/sh
cmd=${1:-}
case "$cmd" in
	--version)
		printf '%s\n' 'cargo 1.86.0 (adf9b6ad1 2025-02-28)'
		;;
	clippy)
		if [ "${OSMAP_TEST_MISSING_CLIPPY:-0}" = "1" ]; then
			exit 1
		fi
		if [ "${2:-}" = "--version" ]; then
			printf '%s\n' 'clippy 0.1.86 (05f9846f89 2025-03-31)'
			exit 0
		fi
		exit 0
		;;
	fmt)
		if [ "${OSMAP_TEST_MISSING_RUSTFMT:-0}" = "1" ]; then
			exit 1
		fi
		if [ "${2:-}" = "--version" ]; then
			printf '%s\n' 'rustfmt 1.8.0-stable (05f9846f89 2025-03-31)'
			exit 0
		fi
		exit 0
		;;
	audit)
		if [ "${OSMAP_TEST_MISSING_AUDIT:-0}" = "1" ]; then
			exit 1
		fi
		printf '%s\n' 'cargo-audit 0.22.1'
		;;
	deny)
		if [ "${OSMAP_TEST_MISSING_DENY:-0}" = "1" ]; then
			exit 1
		fi
		printf '%s\n' 'cargo-deny 0.18.3'
		;;
	build|test)
		exit 0
		;;
	tree)
		printf '%s\n' 'osmap v0.1.0 (/tmp/osmap-fixture)'
		printf '%s\n' 'ammonia v4.1.2'
		;;
	*)
		exit 0
		;;
esac
EOF
	chmod +x "$stub_dir/rustc" "$stub_dir/cargo"
}

make_wstg_summary() {
	path=$1
	mode=$2
	python3 - "$repo_root" "$path" "$mode" <<'PY'
import json
import sys
from pathlib import Path

repo = Path(sys.argv[1])
out = Path(sys.argv[2])
mode = sys.argv[3]
mapping = json.loads((repo / "maint/wstg-testing-pack/wstg-asvs-mapping.json").read_text())
results = []
skip_used = False
for item in mapping["tests"]:
    status = "pass"
    message = "fixture pass"
    if mode == "skip-auth" and item["requires_authenticated_coverage"] and not skip_used:
        status = "skip"
        message = "fixture skipped authenticated coverage"
        skip_used = True
    results.append(
        {
            "test_id": item["test_id"],
            "test_name": item["test_name"],
            "status": status,
            "message": message,
            "evidence": [],
            "details": {},
        }
    )
counts = {"pass": sum(1 for item in results if item["status"] == "pass"), "fail": 0, "warning": 0, "skip": sum(1 for item in results if item["status"] == "skip"), "not_applicable": 0}
summary = {
    "generated_at": "2026-05-02T00:00:00+00:00",
    "target": "https://mail.blackbagsecurity.com",
    "commands": ["fixture"],
    "release_mode": True,
    "authenticated_proof": {
        "login": True,
        "totp": True,
        "session_issued": True,
        "protected_route_access": True,
        "logout": True,
        "session_invalidated": True,
    },
    "release_errors": [],
    "standards": mapping["standards"],
    "results": results,
    "counts": counts,
    "mapping_file": "wstg-asvs-mapping.json",
}
out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
PY
}

make_mime_html_proof_report() {
	path=$1
	mode=${2:-pass}
	commit_short=$(git -C "$repo_root" rev-parse --short HEAD)
	{
		printf '%s\n' "host=mail.blackbagsecurity.com"
		printf '%s\n' "project_root=${repo_root}"
		printf '%s\n' "commit=${commit_short}"
		printf '%s\n' "build_result=passed"
		printf '%s\n' "helper_runtime_result=passed"
		printf '%s\n' "browser_runtime_result=passed"
		printf '%s\n' "healthz_status=HTTP/1.1 200 OK"
		printf '%s\n' "encoded_header_message_view_status=HTTP/1.1 200 OK"
		printf '%s\n' "sanitized_html_message_view_status=HTTP/1.1 200 OK"
		printf '%s\n' "inline_image_message_view_status=HTTP/1.1 200 OK"
		printf '%s\n' "inline_image_attachment_download_status=HTTP/1.1 200 OK"
		printf '%s\n' "attachment_metadata_message_view_status=HTTP/1.1 200 OK"
		printf '%s\n' "delivery_status_attachment_download_status=HTTP/1.1 200 OK"
		printf '%s\n' "original_message_attachment_download_status=HTTP/1.1 200 OK"
		printf '%s\n' "encoded_body_marker_audit_leakage=absent"
		printf '%s\n' "sanitized_html_body_marker_audit_leakage=absent"
		printf '%s\n' "inline_image_body_marker_audit_leakage=absent"
		printf '%s\n' "delivery_status_body_marker_audit_leakage=absent"
		printf '%s\n' "original_message_body_marker_audit_leakage=absent"
		if [ "$mode" = "forbidden" ]; then
			printf '%s\n' "leaked_cookie=osmap_session=redacted-fixture"
		fi
		printf '%s\n' "message_cleanup=attempted"
		printf '%s\n' "result=v3_mime_html_live_proof_passed"
	} > "$path"
}

make_evidence() {
	case_dir=$1
	mkdir -p "$case_dir"
	v2_a="$case_dir/v2-readiness.txt"
	v2_b="$case_dir/v2-service-guard.txt"
	host_a="$case_dir/edge.txt"
	host_b="$case_dir/exposure.txt"
	host_c="$case_dir/service.txt"
	tls="$case_dir/tls-cbc-cleanup.txt"
	resource_timeout="$case_dir/resource-timeout.txt"
	mime_html_proof="$case_dir/latest-host-v3-mime-html-proof-report.txt"
	wstg="$case_dir/wstg-summary.json"
	for path in "$v2_a" "$v2_b" "$host_a" "$host_b" "$host_c" "$tls" "$resource_timeout"; do
		printf '%s\n' "sanitized fixture evidence for $(basename "$path")" > "$path"
	done
	make_mime_html_proof_report "$mime_html_proof" pass
	make_wstg_summary "$wstg" pass
	printf '%s\n' "$v2_a $v2_b"
	printf '%s\n' "$host_a $host_b $host_c"
	printf '%s\n' "$tls"
	printf '%s\n' "$resource_timeout"
	printf '%s\n' "$mime_html_proof"
	printf '%s\n' "$wstg"
}

run_release_case() {
	case_name=$1
	shift
	case_dir="$tmp_root/$case_name"
	stub_dir="$case_dir/bin"
	make_stubs "$stub_dir"
	evidence="$(make_evidence "$case_dir")"
	v2_paths=$(printf '%s\n' "$evidence" | sed -n '1p')
	host_paths=$(printf '%s\n' "$evidence" | sed -n '2p')
	tls_paths=$(printf '%s\n' "$evidence" | sed -n '3p')
	resource_timeout_paths=$(printf '%s\n' "$evidence" | sed -n '4p')
	mime_html_proof_path=$(printf '%s\n' "$evidence" | sed -n '5p')
	wstg_path=$(printf '%s\n' "$evidence" | sed -n '6p')
	env \
		PATH="$stub_dir:$PATH" \
		OSMAP_SECURITY_PROFILE=release \
		OSMAP_RELEASE_EVIDENCE_DIR="$case_dir" \
		OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$case_dir/dependency-inventory.txt" \
		OSMAP_RELEASE_SUMMARY_JSON="$case_dir/summary.json" \
		OSMAP_RELEASE_SUMMARY_MD="$case_dir/summary.md" \
		OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$case_dir/evidence.tar.gz" \
		OSMAP_RELEASE_WSTG_SUMMARY_PATH="$wstg_path" \
		OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$v2_paths" \
		OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$host_paths" \
		OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$tls_paths" \
		OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$resource_timeout_paths" \
		OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$mime_html_proof_path" \
		OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
		"$@" \
		sh "$release_check" > "$case_dir/output.txt" 2>&1
}

assert_fails() {
	name=$1
	shift
	if run_release_case "$name" "$@"; then
		echo "expected $name to fail" >&2
		exit 1
	fi
}

assert_fails cargo-skipped PATH="/bin:/usr/bin"
assert_fails missing-clippy OSMAP_TEST_MISSING_CLIPPY=1
assert_fails missing-rustfmt OSMAP_TEST_MISSING_RUSTFMT=1
assert_fails missing-supply-chain-tool OSMAP_TEST_MISSING_AUDIT=1

skip_case="$tmp_root/auth-skip"
mkdir -p "$skip_case/bin"
make_stubs "$skip_case/bin"
evidence="$(make_evidence "$skip_case")"
skip_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
skip_host=$(printf '%s\n' "$evidence" | sed -n '2p')
skip_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
skip_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '4p')
skip_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '5p')
skip_wstg="$skip_case/wstg-summary.json"
make_wstg_summary "$skip_wstg" skip-auth
if env \
	PATH="$skip_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$skip_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$skip_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$skip_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$skip_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$skip_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$skip_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$skip_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$skip_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$skip_tls" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$skip_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$skip_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$skip_case/output.txt" 2>&1; then
	echo "expected authenticated WSTG skip to fail release mode" >&2
	exit 1
fi

host_case="$tmp_root/missing-host"
mkdir -p "$host_case/bin"
make_stubs "$host_case/bin"
evidence="$(make_evidence "$host_case")"
host_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
host_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
host_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '4p')
host_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '5p')
host_wstg=$(printf '%s\n' "$evidence" | sed -n '6p')
if env \
	PATH="$host_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$host_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$host_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$host_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$host_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$host_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$host_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$host_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$host_case/missing-host.txt" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$host_tls" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$host_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$host_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$host_case/output.txt" 2>&1; then
	echo "expected missing host-readiness evidence to fail release mode" >&2
	exit 1
fi

tls_case="$tmp_root/missing-tls"
mkdir -p "$tls_case/bin"
make_stubs "$tls_case/bin"
evidence="$(make_evidence "$tls_case")"
tls_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
tls_host=$(printf '%s\n' "$evidence" | sed -n '2p')
tls_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '4p')
tls_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '5p')
tls_wstg=$(printf '%s\n' "$evidence" | sed -n '6p')
if env \
	PATH="$tls_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$tls_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$tls_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$tls_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$tls_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$tls_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$tls_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$tls_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$tls_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$tls_case/missing-tls-evidence.txt" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$tls_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$tls_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$tls_case/output.txt" 2>&1; then
	echo "expected missing TLS edge evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "missing TLS edge evidence" "$tls_case/output.txt"

resource_case="$tmp_root/missing-resource-timeout"
mkdir -p "$resource_case/bin"
make_stubs "$resource_case/bin"
evidence="$(make_evidence "$resource_case")"
resource_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
resource_host=$(printf '%s\n' "$evidence" | sed -n '2p')
resource_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
resource_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '5p')
resource_wstg=$(printf '%s\n' "$evidence" | sed -n '6p')
if env \
	PATH="$resource_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$resource_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$resource_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$resource_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$resource_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$resource_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$resource_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$resource_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$resource_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$resource_tls" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$resource_case/missing-resource-timeout-evidence.txt" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$resource_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$resource_case/output.txt" 2>&1; then
	echo "expected missing resource-timeout evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "missing resource-timeout evidence" "$resource_case/output.txt"

mime_missing_case="$tmp_root/missing-mime-html-proof"
mkdir -p "$mime_missing_case/bin"
make_stubs "$mime_missing_case/bin"
evidence="$(make_evidence "$mime_missing_case")"
mime_missing_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
mime_missing_host=$(printf '%s\n' "$evidence" | sed -n '2p')
mime_missing_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
mime_missing_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '4p')
mime_missing_wstg=$(printf '%s\n' "$evidence" | sed -n '6p')
if env \
	PATH="$mime_missing_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$mime_missing_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$mime_missing_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$mime_missing_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$mime_missing_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$mime_missing_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$mime_missing_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$mime_missing_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$mime_missing_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$mime_missing_tls" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$mime_missing_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$mime_missing_case/missing-mime-html-proof.txt" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$mime_missing_case/output.txt" 2>&1; then
	echo "expected missing V3 live MIME/HTML proof evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "missing V3 live MIME/HTML proof evidence" "$mime_missing_case/output.txt"

mime_forbidden_case="$tmp_root/forbidden-mime-html-proof"
mkdir -p "$mime_forbidden_case/bin"
make_stubs "$mime_forbidden_case/bin"
evidence="$(make_evidence "$mime_forbidden_case")"
mime_forbidden_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
mime_forbidden_host=$(printf '%s\n' "$evidence" | sed -n '2p')
mime_forbidden_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
mime_forbidden_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '4p')
mime_forbidden_proof=$(printf '%s\n' "$evidence" | sed -n '5p')
mime_forbidden_wstg=$(printf '%s\n' "$evidence" | sed -n '6p')
make_mime_html_proof_report "$mime_forbidden_proof" forbidden
if env \
	PATH="$mime_forbidden_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$mime_forbidden_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$mime_forbidden_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$mime_forbidden_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$mime_forbidden_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$mime_forbidden_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$mime_forbidden_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$mime_forbidden_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$mime_forbidden_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$mime_forbidden_tls" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$mime_forbidden_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$mime_forbidden_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$mime_forbidden_case/output.txt" 2>&1; then
	echo "expected forbidden V3 live MIME/HTML proof evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "forbidden proof content present: osmap_session=" "$mime_forbidden_case/output.txt"

success_case="$tmp_root/success"
if ! run_release_case success; then
	echo "expected success fixture to pass release mode" >&2
	cat "$success_case/output.txt" >&2
	exit 1
fi
test -s "$success_case/summary.json"
test -s "$success_case/summary.md"
test -s "$success_case/dependency-inventory.txt"
test -s "$success_case/evidence.tar.gz"
grep -Fq '"skipped_checks": []' "$success_case/summary.json"
grep -Fq '"authenticated_wstg_status": "passed"' "$success_case/summary.json"
grep -Fq '"dependency_inventory_status": "passed"' "$success_case/summary.json"
grep -Fq '"tls_cbc_status": "passed"' "$success_case/summary.json"
grep -Fq '"tls_edge_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq '"resource_timeout_status": "passed"' "$success_case/summary.json"
grep -Fq '"resource_timeout_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq '"v3_mime_html_proof_status": "passed"' "$success_case/summary.json"
grep -Fq '"v3_mime_html_proof_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq 'TLS CBC cleanup: `passed`' "$success_case/summary.md"
grep -Fq 'Resource and timeout hardening: `passed`' "$success_case/summary.md"
grep -Fq 'V3 live MIME and HTML proof: `passed`' "$success_case/summary.md"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "tls-cbc-cleanup.txt"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "resource-timeout.txt"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "latest-host-v3-mime-html-proof-report.txt"

developer_case="$tmp_root/developer"
developer_bin="$tmp_root/developer-bin"
mkdir -p "$developer_bin"
cat > "$developer_bin/cargo" <<'EOF'
#!/bin/sh
exit 127
EOF
cat > "$developer_bin/rustc" <<'EOF'
#!/bin/sh
exit 127
EOF
chmod +x "$developer_bin/cargo" "$developer_bin/rustc"
if PATH="$developer_bin:$PATH" OSMAP_SECURITY_PROFILE=developer OSMAP_SKIP_V3_RELEASE_CHECK_TEST=1 sh "$repo_root/maint/security/osmap-security-check.sh" > "$developer_case.out" 2>&1; then
	grep -Fq "skipping cargo-based security-check phases" "$developer_case.out"
else
	echo "developer partial mode should continue when cargo is unavailable" >&2
	cat "$developer_case.out" >&2
	exit 1
fi

echo "V3 release-check fail-closed tests passed"
