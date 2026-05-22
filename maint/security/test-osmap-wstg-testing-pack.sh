#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
pack_dir="$repo_root/maint/wstg-testing-pack"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-wstg-pack-test.XXXXXX")
cleanup() {
	rm -rf "$tmp_root"
}
trap cleanup EXIT INT TERM

if ! command -v python3 >/dev/null 2>&1; then
	echo "ERROR: python3 is required for the WSTG testing pack" >&2
	exit 1
fi

echo "validating WSTG runner syntax"
python3 -m py_compile "$pack_dir/run-wstg-pack.py"

echo "validating WSTG mapping and manifest"
python3 - "$pack_dir" <<'PY'
import csv
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())

required_test_fields = {
    "test_id",
    "test_name",
    "script_path",
    "wstg",
    "wstg_section",
    "asvs",
    "asvs_section",
    "owasp_top_10_2025",
    "test_type",
    "expected_result",
    "evidence_produced",
    "release_required",
    "requires_authenticated_coverage",
    "requires_totp",
    "safe_for_release",
    "severity_if_failed",
}
top10_categories = {
    "A01:2025",
    "A02:2025",
    "A03:2025",
    "A04:2025",
    "A05:2025",
    "A06:2025",
    "A07:2025",
    "A08:2025",
    "A09:2025",
    "A10:2025",
}
seen = set()
top10_release_tests = {category: [] for category in top10_categories}
for item in mapping["tests"]:
    missing = required_test_fields - set(item)
    if missing:
        raise SystemExit(f"{item.get('test_id', '<unknown>')} missing fields: {sorted(missing)}")
    if item["test_id"] in seen:
        raise SystemExit(f"duplicate test_id: {item['test_id']}")
    seen.add(item["test_id"])
    if not all(value.startswith("WSTG-v42-") for value in item["wstg"]):
        raise SystemExit(f"{item['test_id']} contains non-v4.2 WSTG identifier")
    if not all(value.startswith("v5.0.0-") for value in item["asvs"]):
        raise SystemExit(f"{item['test_id']} contains non-ASVS-5.0.0 identifier")
    if not item["owasp_top_10_2025"]:
        raise SystemExit(f"{item['test_id']} must map to at least one OWASP Top 10 2025 category")
    unknown_top10 = set(item["owasp_top_10_2025"]) - top10_categories
    if unknown_top10:
        raise SystemExit(f"{item['test_id']} contains unknown OWASP Top 10 2025 category: {sorted(unknown_top10)}")
    for field in ["release_required", "requires_authenticated_coverage", "requires_totp", "safe_for_release"]:
        if not isinstance(item[field], bool):
            raise SystemExit(f"{item['test_id']} {field} must be boolean")
    is_authenticated = "authenticated" in item["test_type"]
    if item["requires_authenticated_coverage"] != is_authenticated:
        raise SystemExit(f"{item['test_id']} authenticated release metadata does not match test_type")
    if item["requires_totp"] != item["requires_authenticated_coverage"]:
        raise SystemExit(f"{item['test_id']} TOTP metadata must match authenticated coverage requirement")
    if item["release_required"] and not item["safe_for_release"]:
        raise SystemExit(f"{item['test_id']} is release-required but not safe_for_release")
    if item["release_required"] and item["safe_for_release"]:
        for category in item["owasp_top_10_2025"]:
            top10_release_tests[category].append(item["test_id"])
    script_path = pack / item["script_path"]
    if not script_path.exists():
        raise SystemExit(f"{item['test_id']} script_path does not exist: {script_path}")

for gap in mapping.get("gaps", []):
    unknown_top10 = set(gap.get("owasp_top_10_2025", [])) - top10_categories
    if unknown_top10:
        raise SystemExit(f"{gap.get('gap_id', '<unknown>')} contains unknown OWASP Top 10 2025 category: {sorted(unknown_top10)}")

missing_top10 = [category for category, tests in sorted(top10_release_tests.items()) if not tests]
if missing_top10:
    raise SystemExit(f"missing release-required OWASP Top 10 2025 test coverage: {missing_top10}")

manifest_paths = []
with (pack / "MANIFEST.csv").open(newline="") as handle:
    for row in csv.DictReader(handle):
        manifest_paths.append(row["path"])
for rel_path in manifest_paths:
    if not (pack / rel_path).exists():
        raise SystemExit(f"manifest path does not exist: {rel_path}")

env_text = (pack / ".env.example").read_text()
for key in [
    "OSMAP_BASE_URL=https://mail.blackbagsecurity.com",
    "OSMAP_HOST=mail.blackbagsecurity.com",
    "OSMAP_SSH_HOST=mail",
    "OSMAP_TEST_EMAIL=",
    "OSMAP_TEST_PASSWORD=",
    "OSMAP_TOTP_SECRET=",
    "OSMAP_SECONDARY_EMAIL=",
    "OSMAP_OUTPUT_DIR=",
    "OSMAP_WSTG_REMOTE_REPO=/home/foo/OSMAP",
    "OSMAP_WSTG_EXPECTED_REF=",
    "OSMAP_WSTG_SOURCE_NAME=OWASP Web Security Testing Guide",
    "OSMAP_WSTG_SOURCE_URL=https://owasp.org/www-project-web-security-testing-guide/v42/",
    "OSMAP_WSTG_SOURCE_VERSION=v4.2",
    "OSMAP_WSTG_SOURCE_COMMIT=",
    "OSMAP_WSTG_MATRIX_FILE=wstg-scenario-matrix.v42.json",
    "OSMAP_RATE_LIMIT_DELAY_SECONDS=",
    "OSMAP_ALLOW_AUTHENTICATED_TESTS=false",
]:
    if key not in env_text:
        raise SystemExit(f".env.example missing {key}")

matrix = json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())
allowed_dispositions = {
    "automated",
    "manual",
    "not_applicable",
    "covered_by_other_evidence",
    "deferred",
    "blocked",
}
scenarios = matrix.get("scenarios", [])
if len(scenarios) != 97:
    raise SystemExit(f"unexpected WSTG v4.2 scenario count: {len(scenarios)}")
missing_disposition = [row.get("wstg_id", "<unknown>") for row in scenarios if not row.get("disposition")]
if missing_disposition:
    raise SystemExit(f"WSTG matrix rows missing disposition: {missing_disposition[:10]}")
invalid_disposition = [
    row.get("wstg_id", "<unknown>")
    for row in scenarios
    if row.get("disposition") and row.get("disposition") not in allowed_dispositions
]
if invalid_disposition:
    raise SystemExit(f"WSTG matrix rows have invalid disposition: {invalid_disposition[:10]}")
if not any(row.get("disposition") == "automated" for row in scenarios):
    raise SystemExit("WSTG matrix must identify automated rows")
if not any(row.get("disposition") == "blocked" for row in scenarios):
    raise SystemExit("WSTG matrix must identify blocked rows for remaining due diligence")

runner_text = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "active_matrix_metadata",
    "wstg_source_metadata",
    "OSMAP_WSTG_SOURCE_VERSION",
    "OSMAP_WSTG_SOURCE_COMMIT",
    "OSMAP_WSTG_MATRIX_FILE",
    "latest-track WSTG release evidence must include OSMAP_WSTG_SOURCE_COMMIT",
]:
    if marker not in runner_text:
        raise SystemExit(f"runner missing WSTG source metadata marker {marker}")

print(f"validated {len(mapping['tests'])} mapped WSTG tests across all OWASP Top 10 2025 categories")
PY

echo "validating authenticated draft route WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
draft = tests.get("OSMAP-WSTG-BUSL-002")
if not draft:
    raise SystemExit("OSMAP-WSTG-BUSL-002 missing from WSTG mapping")
required_evidence = {
    "draft_save_missing_csrf.headers",
    "draft_save_cross_origin.headers",
    "draft_save_attachment_limit.headers",
    "draft_delete.headers",
    "draft_send_cleanup.headers",
    "draft_send_resume_after_cleanup.headers",
    "draft_stale_session_rejected.headers",
    "draft_route_static_boundary.txt",
    "draft_route_evidence_redaction.txt",
}
missing = sorted(required_evidence - set(draft["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-BUSL-002 missing evidence markers: {missing}")
if draft["requires_authenticated_coverage"] is not True or draft["requires_totp"] is not True:
    raise SystemExit("OSMAP-WSTG-BUSL-002 must remain authenticated and TOTP-gated")
for category in ["A01:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"]:
    if category not in draft["owasp_top_10_2025"]:
        raise SystemExit(f"OSMAP-WSTG-BUSL-002 missing {category} mapping")
coverage = (pack / "COVERAGE.md").read_text()
if "OSMAP-WSTG-BUSL-002" not in coverage:
    raise SystemExit("COVERAGE.md missing OSMAP-WSTG-BUSL-002")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_draft_routes_authenticated",
    "draft_route_evidence_redaction",
    "store_body_evidence=False",
    "draft_save_attachment_limit",
    "if send_draft_id:",
    'throttle_attempts_default = "6" if release_mode else "3"',
]:
    if marker not in runner:
        raise SystemExit(f"runner missing draft marker {marker}")
print("authenticated draft route WSTG mapping validated")
PY

echo "validating authenticated source-attachment WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
source = tests.get("OSMAP-WSTG-BUSL-003")
if not source:
    raise SystemExit("OSMAP-WSTG-BUSL-003 missing from WSTG mapping")
required_evidence = {
    "source_attachment_live_report.txt",
    "source_attachment_static_boundary.txt",
    "source_attachment_evidence_redaction.txt",
}
missing = sorted(required_evidence - set(source["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-BUSL-003 missing evidence markers: {missing}")
if source["requires_authenticated_coverage"] is not True or source["requires_totp"] is not True:
    raise SystemExit("OSMAP-WSTG-BUSL-003 must remain authenticated and TOTP-gated")
for category in ["A01:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"]:
    if category not in source["owasp_top_10_2025"]:
        raise SystemExit(f"OSMAP-WSTG-BUSL-003 missing {category} mapping")
coverage = (pack / "COVERAGE.md").read_text()
if "OSMAP-WSTG-BUSL-003" not in coverage:
    raise SystemExit("COVERAGE.md missing OSMAP-WSTG-BUSL-003")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_source_attachments_authenticated",
    "source_attachment_live_report",
    "source_attachment_evidence_redaction",
    "osmap-live-validate-v3-source-attachments.ksh",
    'os.environ.get("OSMAP_WSTG_REMOTE_REPO", "/home/foo/OSMAP")',
    'os.environ.get("OSMAP_WSTG_EXPECTED_REF", local_git_head())',
    "remote repo ref mismatch",
    "selected_attachment_body_marker_preserved=yes",
    "real_password_plus_totp_with_temporary_mailbox_hash",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing source-attachment marker {marker}")
if "git reset --hard origin/main" in runner:
    raise SystemExit("runner must not mutate the remote checkout before host-assisted WSTG evidence")
validator = (pack.parents[1] / "maint" / "live" / "osmap-live-validate-v3-source-attachments.ksh").read_text()
for marker in [
    "include_original_attachment_1",
    "include_original_attachment_2",
    "tampered_mailbox_status",
    "tampered_uid_status",
    "tampered_part_status",
    "stale_source_status",
    "No password, password hash, TOTP material, session cookie, CSRF token, private message body, attachment body",
]:
    if marker not in validator:
        raise SystemExit(f"source-attachment validator missing marker {marker}")
print("authenticated source-attachment WSTG mapping validated")
PY

echo "validating command-injection WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
command = tests.get("OSMAP-WSTG-INPV-003")
if not command:
    raise SystemExit("OSMAP-WSTG-INPV-003 missing from WSTG mapping")
required_evidence = {
    "command_injection_probe_matrix.txt",
    "command_injection_host_evidence.txt",
    "command_injection_redaction.txt",
}
missing = sorted(required_evidence - set(command["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-INPV-003 missing evidence markers: {missing}")
if command["wstg"] != ["WSTG-v42-INPV-12"]:
    raise SystemExit("OSMAP-WSTG-INPV-003 must map to WSTG-v42-INPV-12")
if command["requires_authenticated_coverage"] is not True or command["requires_totp"] is not True:
    raise SystemExit("OSMAP-WSTG-INPV-003 must remain authenticated and TOTP-gated")
for category in ["A05:2025", "A09:2025", "A10:2025"]:
    if category not in command["owasp_top_10_2025"]:
        raise SystemExit(f"OSMAP-WSTG-INPV-003 missing {category} mapping")
coverage = (pack / "COVERAGE.md").read_text()
if "OSMAP-WSTG-INPV-003" not in coverage or "WSTG-v42-INPV-12" not in coverage:
    raise SystemExit("COVERAGE.md missing command-injection coverage")
readme = (pack / "README.md").read_text()
if "OSMAP-WSTG-INPV-003" not in readme or "command-injection" not in readme.lower():
    raise SystemExit("README.md missing command-injection operator wording")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_command_injection",
    "OSMAP_INPV12_OUTPUT_",
    "COMMAND_INJECTION_SLEEP_SECONDS",
    "command_injection_host_evidence",
    "response_truncated_before_absence_assertions_completed",
    "reflected_command_output_canary",
    "uid_gid_output",
    "passwd_style_output",
    "/var/log/nginx/mail.access.log",
    "/var/lib/osmap/audit/serve.log",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing command-injection marker {marker}")
print("command-injection WSTG mapping validated")
PY

echo "validating live WSTG evidence mappings"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
expected = {
    "OSMAP-WSTG-CLNT-002": {"mime_html_live_report.txt", "static_html_rendering.txt"},
    "OSMAP-WSTG-BUSL-001": {"mime_html_live_report.txt", "static_attachment_handling.txt"},
    "OSMAP-WSTG-BUSL-004": {"bulk_folder_actions_live_report.txt", "static_bulk_folder_actions.txt"},
    "OSMAP-WSTG-CONF-007": {"static_dependency_alignment.txt", "dependency_metadata_locked.txt"},
    "OSMAP-WSTG-LOGG-001": {"static_security_logging.txt", "security_logging_evidence_redaction.txt"},
}
for test_id, evidence in expected.items():
    item = tests[test_id]
    missing = sorted(evidence - set(item["evidence_produced"]))
    if missing:
        raise SystemExit(f"{test_id} missing evidence markers: {missing}")
    if item["test_type"] == ["static review"]:
        raise SystemExit(f"{test_id} must not be mapped as static-only WSTG evidence")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_html_rendering_live",
    "test_attachment_live",
    "mime_html_live_evidence",
    "test_bulk_folder_actions_live",
    "osmap-live-validate-v3-mime-html-proof.ksh",
    "osmap-live-validate-archive-shortcut.ksh",
    "X-OSMAP-WSTG-Body-Truncated",
    "proven_top10_coverage",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing live WSTG marker {marker}")
print("live WSTG evidence mappings validated")
PY

echo "validating authenticated source-attachment route skips without credentials"
if ! python3 "$pack_dir/run-wstg-pack.py" \
	--unauthenticated \
	--test-id OSMAP-WSTG-BUSL-003 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root/source-attachment-skip" >/dev/null 2>&1; then
	echo "expected credential-gated source-attachment route test to skip cleanly without credentials" >&2
	exit 1
fi

echo "validating authenticated draft route skips without credentials"
if ! python3 "$pack_dir/run-wstg-pack.py" \
	--unauthenticated \
	--test-id OSMAP-WSTG-BUSL-002 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root/draft-skip" >/dev/null 2>&1; then
	echo "expected credential-gated draft route test to skip cleanly without credentials" >&2
	exit 1
fi

echo "validating command-injection route skips without credentials"
if ! python3 "$pack_dir/run-wstg-pack.py" \
	--unauthenticated \
	--test-id OSMAP-WSTG-INPV-003 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root/command-injection-skip" >/dev/null 2>&1; then
	echo "expected credential-gated command-injection route test to skip cleanly without credentials" >&2
	exit 1
fi

echo "validating WSTG release mode fails on skipped authenticated coverage"
if python3 "$pack_dir/run-wstg-pack.py" \
	--release \
	--test-id OSMAP-WSTG-ATHN-004 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root/release-skip" >/dev/null 2>&1; then
	echo "expected WSTG release mode to fail when authenticated coverage is skipped" >&2
	exit 1
fi

echo "WSTG testing pack validation passed"
