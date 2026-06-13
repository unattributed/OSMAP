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
printf '%s\n' 'rustc 1.94.1 (e408947bf 2026-03-25) (built from a source tarball)'
EOF
	cat > "$stub_dir/cargo" <<'EOF'
#!/bin/sh
cmd=${1:-}
case "$cmd" in
	--version)
		printf '%s\n' 'cargo 1.94.1 (29ea6fb6a 2026-03-24) (built from a source tarball)'
		;;
	clippy)
		if [ "${OSMAP_TEST_MISSING_CLIPPY:-0}" = "1" ]; then
			exit 1
		fi
		if [ "${2:-}" = "--version" ]; then
			printf '%s\n' 'clippy 0.1.94'
			exit 0
		fi
		exit 0
		;;
	fmt)
		if [ "${OSMAP_TEST_MISSING_RUSTFMT:-0}" = "1" ]; then
			exit 1
		fi
		if [ "${2:-}" = "--version" ]; then
			printf '%s\n' 'rustfmt 1.8.0'
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
		if [ "$cmd" = "test" ] && [ -n "${OSMAP_V4_ASSURANCE_REPORT:-}" ]; then
			mkdir -p "$(dirname "$OSMAP_V4_ASSURANCE_REPORT")"
			cat > "$OSMAP_V4_ASSURANCE_REPORT" <<JSON
{
  "schema": "osmap-v4-hostile-assurance-report-v1",
  "status": "passed",
  "assessed_ref": "${OSMAP_V4_ASSURANCE_ASSESSED_REF:-unknown}",
  "generated_at_utc": "${OSMAP_V4_ASSURANCE_GENERATED_AT:-2026-06-12T00:00:00Z}",
  "corpus_root": "tests/testdata/hostile-mail-corpus",
  "release_gate": "maint/security/osmap-v4-hostile-assurance-gate.sh",
  "resource_usage_observations": {
    "mime_max_depth": 4,
    "mime_max_parts": 64,
    "mime_header_count_max": 256,
    "attachment_download_max_bytes": 262144
  },
  "network_assertions": {
    "remote_fetches": 0,
    "beacon_requests": 0,
    "websocket_requests": 0,
    "service_worker_registrations": 0
  },
  "route_backed_observations": {
    "rendered_message_routes": 3,
    "attachment_download_routes": 5,
    "dom_assertions": 3,
    "auto_fetch_surfaces": 0,
    "unsafe_browser_api_references": 0
  },
  "components": [
    {"component": "hostile_corpus_metadata", "status": "passed", "observation": "fixture pass"},
    {"component": "browser_rendered_negative_assertions", "status": "passed", "observation": "fixture pass"},
    {"component": "mime_parser_robustness", "status": "passed", "observation": "fixture pass"},
    {"component": "attachment_deception_handling", "status": "passed", "observation": "fixture pass"},
    {"component": "browser_isolation_verification", "status": "passed", "observation": "fixture pass"}
  ]
}
JSON
		fi
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
top10_coverage = {}
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
    if item.get("release_required") is True and item.get("safe_for_release") is True:
        for category in item.get("owasp_top_10_2025", []):
            top10_coverage.setdefault(category, {"tests": [], "gaps": []})["tests"].append(item["test_id"])
for gap in mapping.get("gaps", []):
    for category in gap.get("owasp_top_10_2025", []):
        top10_coverage.setdefault(category, {"tests": [], "gaps": []})["gaps"].append(gap["gap_id"])
counts = {"pass": sum(1 for item in results if item["status"] == "pass"), "fail": 0, "warning": 0, "skip": sum(1 for item in results if item["status"] == "skip"), "not_applicable": 0}
summary = {
    "generated_at": "2026-05-02T00:00:00+00:00",
    "target": "https://mail.blackbagsecurity.com",
    "commands": ["./run.sh --release --auth-email pilot-primary@example.invalid"] if mode == "missing-human-proof" else ["./run.sh --release --prompt-auth --auth-email pilot-primary@example.invalid"],
    "release_mode": True,
    "owasp_top_10_2025_coverage": top10_coverage,
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

make_tls_standard_report() {
	path=$1
	cat > "$path" <<'EOF'
{
  "certificate_validation": true,
  "failures": [],
  "hostname_validation": true,
  "minimum_tls_version": "TLSv1.2",
  "preferred_tls_version": "TLSv1.3",
  "probes": {
    "tls10": {
      "cipher": "",
      "protocol": "",
      "status": "rejected"
    },
    "tls11": {
      "cipher": "",
      "protocol": "",
      "status": "rejected"
    },
    "tls12": {
      "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384",
      "protocol": "TLSv1.2",
      "status": "passed",
      "strong_cipher": true,
      "verify_ok": true
    },
    "tls13": {
      "cipher": "TLS_AES_256_GCM_SHA384",
      "protocol": "TLSv1.3",
      "status": "passed",
      "strong_cipher": true,
      "verify_ok": true
    },
    "weak_tls12_ciphers": {
      "AES128-SHA": {
        "cipher": "",
        "protocol": "",
        "status": "rejected"
      },
      "AES256-SHA": {
        "cipher": "",
        "protocol": "",
        "status": "rejected"
      },
      "ECDHE-RSA-AES256-SHA384": {
        "cipher": "",
        "protocol": "",
        "status": "rejected"
      }
    }
  },
  "result": "tls_standard_passed",
  "target": "https://mail.blackbagsecurity.com:443"
}
EOF
}

make_pilot_rehearsal_report() {
	path=$1
	commit_short=$(git -C "$repo_root" rev-parse --short HEAD)
	{
		printf '%s\n' "host=mail.blackbagsecurity.com"
		printf '%s\n' "commit=${commit_short}"
		printf '%s\n' "workflow_inventory=docs/PILOT_WORKFLOW_INVENTORY.md"
		printf '%s\n' "credential_totp_login=passed"
		printf '%s\n' "mailbox_listing=passed"
		printf '%s\n' "message_view=passed"
		printf '%s\n' "attachment_download=passed"
		printf '%s\n' "bounded_search=passed"
		printf '%s\n' "compose_send=passed"
		printf '%s\n' "reply_forward=passed"
		printf '%s\n' "draft_save_resume=passed"
		printf '%s\n' "selected_source_attachments=passed"
		printf '%s\n' "bounded_bulk_folder_actions=passed"
		printf '%s\n' "session_logout_revoke=passed"
		printf '%s\n' "roundcube_fallback_required=none"
		printf '%s\n' "sanitized_evidence=true"
		printf '%s\n' "result=v3_pilot_rehearsal_passed"
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
	tls_standard="$case_dir/tls-standard.json"
	resource_timeout="$case_dir/resource-timeout.txt"
	helper_boundary="$case_dir/latest-host-helper-boundary-report.txt"
	mime_html_proof="$case_dir/latest-host-v3-mime-html-proof-report.txt"
	pilot_rehearsal="$case_dir/latest-host-v3-pilot-rehearsal-report.txt"
	wstg="$case_dir/wstg-summary.json"
	for path in "$v2_a" "$v2_b" "$host_a" "$host_b" "$host_c" "$tls" "$resource_timeout" "$helper_boundary"; do
		printf '%s\n' "sanitized fixture evidence for $(basename "$path")" > "$path"
	done
	make_tls_standard_report "$tls_standard"
	make_mime_html_proof_report "$mime_html_proof" pass
	make_pilot_rehearsal_report "$pilot_rehearsal"
	make_wstg_summary "$wstg" pass
	printf '%s\n' "$v2_a $v2_b"
	printf '%s\n' "$host_a $host_b $host_c"
	printf '%s\n' "$tls"
	printf '%s\n' "$tls_standard"
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
	tls_standard_path=$(printf '%s\n' "$evidence" | sed -n '4p')
	resource_timeout_paths=$(printf '%s\n' "$evidence" | sed -n '5p')
	mime_html_proof_path=$(printf '%s\n' "$evidence" | sed -n '6p')
	wstg_path=$(printf '%s\n' "$evidence" | sed -n '7p')
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
		OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$tls_standard_path" \
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
skip_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
skip_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
skip_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
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
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$skip_tls_standard" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$skip_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$skip_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$skip_case/output.txt" 2>&1; then
	echo "expected authenticated WSTG skip to fail release mode" >&2
	exit 1
fi

human_proof_case="$tmp_root/missing-human-proof"
mkdir -p "$human_proof_case/bin"
make_stubs "$human_proof_case/bin"
evidence="$(make_evidence "$human_proof_case")"
human_proof_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
human_proof_host=$(printf '%s\n' "$evidence" | sed -n '2p')
human_proof_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
human_proof_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
human_proof_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
human_proof_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
human_proof_wstg="$human_proof_case/wstg-summary.json"
make_wstg_summary "$human_proof_wstg" missing-human-proof
if env \
	PATH="$human_proof_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$human_proof_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$human_proof_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$human_proof_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$human_proof_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$human_proof_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$human_proof_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$human_proof_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$human_proof_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$human_proof_tls" \
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$human_proof_tls_standard" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$human_proof_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$human_proof_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$human_proof_case/output.txt" 2>&1; then
	echo "expected missing human credential/TOTP proof evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "authenticated proof missing human credential/TOTP prompt evidence" "$human_proof_case/output.txt"

host_case="$tmp_root/missing-host"
mkdir -p "$host_case/bin"
make_stubs "$host_case/bin"
evidence="$(make_evidence "$host_case")"
host_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
host_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
host_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
host_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
host_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
host_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
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
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$host_tls_standard" \
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
tls_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
tls_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
tls_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
tls_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
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
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$tls_tls_standard" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$tls_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$tls_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$tls_case/output.txt" 2>&1; then
	echo "expected missing TLS edge evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "missing TLS edge evidence" "$tls_case/output.txt"

tls_standard_case="$tmp_root/missing-tls-standard"
mkdir -p "$tls_standard_case/bin"
make_stubs "$tls_standard_case/bin"
evidence="$(make_evidence "$tls_standard_case")"
tls_standard_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
tls_standard_host=$(printf '%s\n' "$evidence" | sed -n '2p')
tls_standard_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
tls_standard_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
tls_standard_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
tls_standard_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
if env \
	PATH="$tls_standard_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$tls_standard_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$tls_standard_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$tls_standard_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$tls_standard_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$tls_standard_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$tls_standard_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$tls_standard_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$tls_standard_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$tls_standard_tls" \
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$tls_standard_case/missing-tls-standard.json" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$tls_standard_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$tls_standard_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$tls_standard_case/output.txt" 2>&1; then
	echo "expected missing TLS standard evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "missing TLS standard evidence" "$tls_standard_case/output.txt"

tls_weak_case="$tmp_root/missing-weak-tls-cipher-evidence"
mkdir -p "$tls_weak_case/bin"
make_stubs "$tls_weak_case/bin"
evidence="$(make_evidence "$tls_weak_case")"
tls_weak_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
tls_weak_host=$(printf '%s\n' "$evidence" | sed -n '2p')
tls_weak_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
tls_weak_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
tls_weak_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
tls_weak_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
tls_weak_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
python3 - "$tls_weak_tls_standard" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
report["probes"].pop("weak_tls12_ciphers", None)
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if env \
	PATH="$tls_weak_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$tls_weak_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$tls_weak_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$tls_weak_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$tls_weak_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$tls_weak_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$tls_weak_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$tls_weak_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$tls_weak_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$tls_weak_tls" \
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$tls_weak_tls_standard" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$tls_weak_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$tls_weak_mime_html_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$tls_weak_case/output.txt" 2>&1; then
	echo "expected missing weak TLS cipher evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "weak TLS 1.2 cipher rejection probes are missing" "$tls_weak_case/output.txt"

resource_case="$tmp_root/missing-resource-timeout"
mkdir -p "$resource_case/bin"
make_stubs "$resource_case/bin"
evidence="$(make_evidence "$resource_case")"
resource_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
resource_host=$(printf '%s\n' "$evidence" | sed -n '2p')
resource_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
resource_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
resource_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
resource_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
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
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$resource_tls_standard" \
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
mime_missing_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
mime_missing_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
mime_missing_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
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
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$mime_missing_tls_standard" \
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
mime_forbidden_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
mime_forbidden_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
mime_forbidden_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
mime_forbidden_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
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
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$mime_forbidden_tls_standard" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$mime_forbidden_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$mime_forbidden_proof" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$mime_forbidden_case/output.txt" 2>&1; then
	echo "expected forbidden V3 live MIME/HTML proof evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "forbidden proof content present: osmap_session=" "$mime_forbidden_case/output.txt"

pilot_missing_case="$tmp_root/missing-v3-pilot-rehearsal"
mkdir -p "$pilot_missing_case/bin"
make_stubs "$pilot_missing_case/bin"
evidence="$(make_evidence "$pilot_missing_case")"
pilot_missing_v2=$(printf '%s\n' "$evidence" | sed -n '1p')
pilot_missing_host=$(printf '%s\n' "$evidence" | sed -n '2p')
pilot_missing_tls=$(printf '%s\n' "$evidence" | sed -n '3p')
pilot_missing_tls_standard=$(printf '%s\n' "$evidence" | sed -n '4p')
pilot_missing_resource_timeout=$(printf '%s\n' "$evidence" | sed -n '5p')
pilot_missing_mime_html_proof=$(printf '%s\n' "$evidence" | sed -n '6p')
pilot_missing_wstg=$(printf '%s\n' "$evidence" | sed -n '7p')
if env \
	PATH="$pilot_missing_case/bin:$PATH" \
	OSMAP_SECURITY_PROFILE=release \
	OSMAP_RELEASE_EVIDENCE_DIR="$pilot_missing_case" \
	OSMAP_RELEASE_DEPENDENCY_INVENTORY_PATH="$pilot_missing_case/dependency-inventory.txt" \
	OSMAP_RELEASE_SUMMARY_JSON="$pilot_missing_case/summary.json" \
	OSMAP_RELEASE_SUMMARY_MD="$pilot_missing_case/summary.md" \
	OSMAP_RELEASE_SANITIZED_ARCHIVE_PATH="$pilot_missing_case/evidence.tar.gz" \
	OSMAP_RELEASE_WSTG_SUMMARY_PATH="$pilot_missing_wstg" \
	OSMAP_RELEASE_V2_CARRY_FORWARD_EVIDENCE="$pilot_missing_v2" \
	OSMAP_RELEASE_HOST_READINESS_EVIDENCE="$pilot_missing_host" \
	OSMAP_RELEASE_TLS_EDGE_EVIDENCE="$pilot_missing_tls" \
	OSMAP_RELEASE_TLS_STANDARD_EVIDENCE="$pilot_missing_tls_standard" \
	OSMAP_RELEASE_RESOURCE_TIMEOUT_EVIDENCE="$pilot_missing_resource_timeout" \
	OSMAP_RELEASE_V3_MIME_HTML_PROOF_REPORT="$pilot_missing_mime_html_proof" \
	OSMAP_RELEASE_V3_PILOT_REHEARSAL_EVIDENCE="$pilot_missing_case/missing-v3-pilot-rehearsal.txt docs/PILOT_WORKFLOW_INVENTORY.md" \
	OSMAP_RELEASE_SUPPLY_CHAIN_COMMAND=true \
	sh "$release_check" > "$pilot_missing_case/output.txt" 2>&1; then
	echo "expected missing V3 pilot rehearsal evidence to fail release mode" >&2
	exit 1
fi
grep -Fq "missing V3 pilot rehearsal evidence" "$pilot_missing_case/output.txt"
if grep -Fq "Traceback" "$pilot_missing_case/output.txt"; then
	echo "missing V3 pilot rehearsal evidence should fail without a Python traceback" >&2
	cat "$pilot_missing_case/output.txt" >&2
	exit 1
fi

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
grep -Fq '"tls_standard_status": "passed"' "$success_case/summary.json"
grep -Fq '"tls_standard_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq '"resource_timeout_status": "passed"' "$success_case/summary.json"
grep -Fq '"resource_timeout_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq '"v3_mime_html_proof_status": "passed"' "$success_case/summary.json"
grep -Fq '"v3_mime_html_proof_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq '"v3_pilot_rehearsal_status": "passed"' "$success_case/summary.json"
grep -Fq '"v3_pilot_rehearsal_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq '"v4_hostile_assurance_status": "passed"' "$success_case/summary.json"
grep -Fq '"v4_hostile_assurance_evidence_files_checked": [' "$success_case/summary.json"
grep -Fq 'TLS CBC cleanup: `passed`' "$success_case/summary.md"
grep -Fq 'TLS standard validation: `passed`' "$success_case/summary.md"
grep -Fq 'Resource and timeout hardening: `passed`' "$success_case/summary.md"
grep -Fq 'V3 live MIME and HTML proof: `passed`' "$success_case/summary.md"
grep -Fq 'V3 pilot rehearsal: `passed`' "$success_case/summary.md"
grep -Fq 'V4 hostile-content assurance: `passed`' "$success_case/summary.md"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "tls-cbc-cleanup.txt"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "tls-standard.json"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "resource-timeout.txt"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "latest-host-v3-mime-html-proof-report.txt"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "latest-host-v3-pilot-rehearsal-report.txt"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "osmap-v4-hostile-assurance-report.json"
tar -tzf "$success_case/evidence.tar.gz" | grep -Fq "osmap-v4-hostile-assurance-evidence.tar.gz"

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
