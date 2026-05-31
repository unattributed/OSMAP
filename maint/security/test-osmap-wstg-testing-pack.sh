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
    "OSMAP_WSTG_SOURCE_VERSION=latest",
    "OSMAP_WSTG_SOURCE_COMMIT=7dea71b751ea76f792b89186655739720b614d9a",
    "OSMAP_WSTG_MATRIX_FILE=wstg-scenario-matrix.latest.json",
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
blocked = [row.get("wstg_id", "<unknown>") for row in scenarios if row.get("disposition") == "blocked"]
if blocked:
    raise SystemExit(f"WSTG matrix must have no blocked rows after ATHN applicability closeout: {blocked[:10]}")
unmapped = [
    row.get("wstg_id", "<unknown>")
    for row in scenarios
    if row.get("current_osmap_mapping_status") != "mapped_in_current_pack"
]
if unmapped:
    raise SystemExit(f"WSTG matrix must map every listed row after ATHN applicability closeout: {unmapped[:10]}")

latest = json.loads((pack / "wstg-scenario-matrix.latest.json").read_text())
expected_latest_commit = "7dea71b751ea76f792b89186655739720b614d9a"
if latest.get("source_repo") != "https://github.com/OWASP/wstg":
    raise SystemExit("latest WSTG matrix must identify the OWASP/wstg repository")
if latest.get("source_branch") != "master":
    raise SystemExit("latest WSTG matrix must identify the source branch")
if latest.get("source_commit") != expected_latest_commit:
    raise SystemExit("latest WSTG matrix source commit is not pinned to the reviewed upstream commit")
latest_scenarios = latest.get("scenarios", [])
if len(latest_scenarios) != 114:
    raise SystemExit(f"unexpected latest WSTG scenario row count: {len(latest_scenarios)}")
latest_pack = latest.get("current_osmap_pack", {})
if latest_pack.get("unique_latest_source_wstg_ids") != 112:
    raise SystemExit("latest WSTG matrix must record 112 unique source WSTG IDs")
if latest_pack.get("latest_source_scenario_rows_mapped_by_current_pack") != 114:
    raise SystemExit("latest WSTG matrix must map all 114 latest source rows")
if latest_pack.get("latest_source_scenario_rows_not_mapped_by_current_pack") != 0:
    raise SystemExit("latest WSTG matrix must have zero unmapped latest source rows")
if sorted(latest_pack.get("source_wstg_ids_with_duplicate_rows", [])) != ["WSTG-APIT-03", "WSTG-INPV-13"]:
    raise SystemExit("latest WSTG matrix must identify reviewed duplicate upstream WSTG IDs")
if latest_pack.get("latest_source_rows_added_or_disambiguated_since_v42") != 17:
    raise SystemExit("latest WSTG matrix must account for added or disambiguated latest rows")
latest_dispositions = latest_pack.get("latest_source_disposition_counts", {})
if latest_dispositions.get("automated") != 70 or latest_dispositions.get("not_applicable") != 44:
    raise SystemExit("latest WSTG matrix disposition counts changed unexpectedly")
latest_unmapped = [
    row.get("scenario_id", "<unknown>")
    for row in latest_scenarios
    if row.get("current_osmap_mapping_status") != "mapped_in_current_pack"
]
if latest_unmapped:
    raise SystemExit(f"latest WSTG matrix has unmapped rows: {latest_unmapped[:10]}")
latest_missing_disposition = [row.get("scenario_id", "<unknown>") for row in latest_scenarios if not row.get("disposition")]
if latest_missing_disposition:
    raise SystemExit(f"latest WSTG matrix rows missing disposition: {latest_missing_disposition[:10]}")
latest_blocked = [row.get("scenario_id", "<unknown>") for row in latest_scenarios if row.get("disposition") == "blocked"]
if latest_blocked:
    raise SystemExit(f"latest WSTG matrix must not have blocked rows: {latest_blocked[:10]}")
for scenario_id, expected_test in {
    "WSTG-latest-CONF-13": "OSMAP-WSTG-INPV-005",
    "WSTG-latest-CONF-14": "OSMAP-WSTG-CONF-002",
    "WSTG-latest-ATHN-11": "OSMAP-WSTG-ATHN-004",
    "WSTG-latest-SESS-10": "OSMAP-WSTG-SESS-006",
    "WSTG-latest-SESS-11": "OSMAP-WSTG-SESS-006",
    "WSTG-latest-INPV-20": "OSMAP-WSTG-INPV-005",
    "WSTG-latest-INPV-21": "OSMAP-WSTG-INPV-007",
    "WSTG-latest-APIT-99": "OSMAP-WSTG-APIT-001",
}.items():
    row = next((item for item in latest_scenarios if item.get("scenario_id") == scenario_id), None)
    if row is None:
        raise SystemExit(f"latest WSTG matrix missing {scenario_id}")
    if expected_test not in row.get("evidence_reference", []):
        raise SystemExit(f"{scenario_id} must reference {expected_test}")

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

echo "validating identity lifecycle WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
idnt = tests.get("OSMAP-WSTG-IDNT-001")
if not idnt:
    raise SystemExit("OSMAP-WSTG-IDNT-001 missing")
expected = ["WSTG-v42-IDNT-01", "WSTG-v42-IDNT-02", "WSTG-v42-IDNT-03", "WSTG-v42-IDNT-05"]
if idnt["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-IDNT-001 must map IDNT-01, IDNT-02, IDNT-03, and IDNT-05")
if idnt["requires_authenticated_coverage"] or idnt["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-IDNT-001 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-IDNT-001", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing identity lifecycle marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_identity_lifecycle_applicability",
    "identity_lifecycle_static.txt",
    "single browser end-user role",
    "no self-service registration",
    "no browser account provisioning",
    "DEFAULT_USERNAME_MAX_LEN",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing identity lifecycle marker {marker}")
doc = (repo / "docs" / "V3_IDENTITY_LIFECYCLE_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-IDNT-001",
    "single browser end-user role",
    "no self-service registration",
    "Account provisioning is not a browser-facing OSMAP feature",
    "DEFAULT_USERNAME_MAX_LEN",
]:
    if marker not in doc:
        raise SystemExit(f"identity lifecycle doc missing marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if "OSMAP-WSTG-IDNT-001" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must reference OSMAP-WSTG-IDNT-001")
if rows["WSTG-v42-IDNT-05"]["disposition"] != "automated":
    raise SystemExit("IDNT-05 must be automated by OSMAP-WSTG-IDNT-001")
for wstg_id in ["WSTG-v42-IDNT-01", "WSTG-v42-IDNT-02", "WSTG-v42-IDNT-03"]:
    if rows[wstg_id]["disposition"] != "not_applicable":
        raise SystemExit(f"{wstg_id} must be not-applicable with evidence")
print("identity lifecycle WSTG mapping validated")
PY

echo "validating authentication applicability WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
athn = tests.get("OSMAP-WSTG-ATHN-005")
if not athn:
    raise SystemExit("OSMAP-WSTG-ATHN-005 missing")
expected = [
    "WSTG-v42-ATHN-02",
    "WSTG-v42-ATHN-04",
    "WSTG-v42-ATHN-05",
    "WSTG-v42-ATHN-07",
    "WSTG-v42-ATHN-08",
    "WSTG-v42-ATHN-09",
]
if athn["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-ATHN-005 must map the remaining ATHN blocked rows")
if athn["requires_authenticated_coverage"] or athn["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-ATHN-005 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-ATHN-005", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing authentication applicability marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_authentication_feature_applicability",
    "authentication_feature_static.txt",
    "no default credentials",
    "no browser authentication bypass route",
    "no remember-password feature",
    "no browser password policy surface",
    "no security questions",
    "no browser password change or reset functionality",
    "DEFAULT_PASSWORD_MAX_LEN",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing authentication applicability marker {marker}")
doc = (repo / "docs" / "V3_AUTHENTICATION_APPLICABILITY_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-ATHN-005",
    "no default credentials",
    "no browser authentication bypass route",
    "no remember-password feature",
    "no browser password policy surface",
    "no security questions",
    "no browser password change or reset functionality",
    "RequiredSecondFactor::Totp",
]:
    if marker not in doc:
        raise SystemExit(f"authentication applicability doc missing marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if "OSMAP-WSTG-ATHN-005" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must reference OSMAP-WSTG-ATHN-005")
if rows["WSTG-v42-ATHN-04"]["disposition"] != "automated":
    raise SystemExit("ATHN-04 must be automated by OSMAP-WSTG-ATHN-005")
for wstg_id in ["WSTG-v42-ATHN-02", "WSTG-v42-ATHN-05", "WSTG-v42-ATHN-07", "WSTG-v42-ATHN-08", "WSTG-v42-ATHN-09"]:
    if rows[wstg_id]["disposition"] != "not_applicable":
        raise SystemExit(f"{wstg_id} must be not-applicable with evidence")
print("authentication applicability WSTG mapping validated")
PY

echo "validating session lifecycle WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
session = tests.get("OSMAP-WSTG-SESS-006")
if not session:
    raise SystemExit("OSMAP-WSTG-SESS-006 missing from WSTG mapping")
expected_wstg = {
    "WSTG-v42-SESS-01",
    "WSTG-v42-SESS-04",
    "WSTG-v42-SESS-06",
    "WSTG-v42-SESS-07",
    "WSTG-v42-SESS-08",
    "WSTG-v42-SESS-09",
}
if set(session["wstg"]) != expected_wstg:
    raise SystemExit("OSMAP-WSTG-SESS-006 must map the remaining session lifecycle rows")
if session["requires_authenticated_coverage"] is not True or session["requires_totp"] is not True:
    raise SystemExit("OSMAP-WSTG-SESS-006 must remain authenticated and TOTP-gated")
required_evidence = {
    "session_lifecycle_login.headers",
    "session_lifecycle_mailboxes.headers",
    "session_lifecycle_logout.headers",
    "session_lifecycle_old_cookie_after_logout.headers",
    "session_lifecycle_stale_cookie.headers",
    "session_lifecycle_static.txt",
    "session_lifecycle_redaction.txt",
}
missing = sorted(required_evidence - set(session["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-SESS-006 missing evidence markers: {missing}")
coverage = (pack / "COVERAGE.md").read_text()
if "OSMAP-WSTG-SESS-006" not in coverage or "WSTG-v42-SESS-07" not in coverage:
    raise SystemExit("COVERAGE.md missing session lifecycle coverage")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_session_lifecycle_policy",
    "session_lifecycle_old_cookie_after_logout",
    "session_lifecycle_stale_cookie",
    "write_session_lifecycle_static_evidence",
    "write_session_lifecycle_redaction_evidence",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing session lifecycle marker {marker}")
doc = (repo / "docs" / "V3_SESSION_LIFECYCLE_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-SESS-006",
    "validate_session_rejects_expired_records",
    "validate_session_auto_revokes_idle_records",
    "simultaneous_session_validations_do_not_corrupt_last_seen",
    "logout_racing_with_validation_leaves_session_revoked",
    "remembered-device cookies",
]:
    if marker not in doc:
        raise SystemExit(f"session lifecycle doc missing marker {marker}")
print("session lifecycle WSTG mapping validated")
PY

echo "validating authorization account-isolation WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
authz = tests.get("OSMAP-WSTG-ATHZ-001")
if not authz:
    raise SystemExit("OSMAP-WSTG-ATHZ-001 missing from WSTG mapping")
if authz["wstg"] != ["WSTG-v42-ATHZ-02", "WSTG-v42-ATHZ-03", "WSTG-v42-ATHZ-04"]:
    raise SystemExit("OSMAP-WSTG-ATHZ-001 must map ATHZ-02/03/04")
if authz["requires_authenticated_coverage"] is not True or authz["requires_totp"] is not True:
    raise SystemExit("OSMAP-WSTG-ATHZ-001 must remain authenticated and TOTP-gated")
required_evidence = {
    "authorization_account_isolation_fixture.txt",
    "authz_cross_user_message.headers",
    "authz_cross_user_attachment.headers",
    "authz_cross_user_sent.headers",
    "authz_cross_user_search.headers",
    "authz_route_bypass_no_cookie.headers",
    "authz_route_bypass_stale_cookie.headers",
    "authorization_account_isolation_static.txt",
    "authorization_account_isolation_redaction.txt",
}
missing = sorted(required_evidence - set(authz["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-ATHZ-001 missing evidence markers: {missing}")
coverage = (pack / "COVERAGE.md").read_text()
if "OSMAP-WSTG-ATHZ-001" not in coverage or "WSTG-v42-ATHZ-02" not in coverage:
    raise SystemExit("COVERAGE.md missing authorization account-isolation coverage")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_authorization_account_isolation",
    "provision_secondary_authorization_fixture",
    "OSMAP_SECONDARY_EMAIL is required",
    "authz_cross_user_message",
    "authz_cross_user_attachment",
    "authz_cross_user_sent",
    "authz_cross_user_search",
    "authorization_account_isolation_redaction",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing authorization account-isolation marker {marker}")
doc = (repo / "docs" / "V3_AUTHORIZATION_ACCOUNT_ISOLATION.md").read_text()
for marker in [
    "OSMAP-WSTG-ATHZ-001",
    "primary authenticated account",
    "secondary controlled mailbox fixture",
    "file_draft_store_scopes_loads_by_owner",
    "MessageMoveThrottleKey::for_canonical_user_and_remote_addr",
    "grant canonical_username",
]:
    if marker not in doc:
        raise SystemExit(f"authorization account-isolation doc missing marker {marker}")
print("authorization account-isolation WSTG mapping validated")
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

echo "validating webmail input-validation WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
webmail = tests.get("OSMAP-WSTG-INPV-004")
if not webmail:
    raise SystemExit("OSMAP-WSTG-INPV-004 missing from WSTG mapping")
if webmail["wstg"] != ["WSTG-v42-INPV-10"]:
    raise SystemExit("OSMAP-WSTG-INPV-004 must map to WSTG-v42-INPV-10")
if webmail["requires_authenticated_coverage"] is not True or webmail["requires_totp"] is not True:
    raise SystemExit("OSMAP-WSTG-INPV-004 must remain authenticated and TOTP-gated")
required_evidence = {
    "webmail_inpv10_subject_newline.headers",
    "webmail_inpv10_recipient_newline.headers",
    "webmail_inpv10_display_name.headers",
    "webmail_inpv10_mailbox_tamper.headers",
    "webmail_inpv10_uid_tamper.headers",
    "webmail_inpv10_search_tamper.headers",
    "webmail_inpv10_attachment_filename.headers",
    "webmail_inpv10_dangerous_content_type.headers",
    "webmail_input_validation_static.txt",
    "webmail_input_validation_redaction.txt",
}
missing = sorted(required_evidence - set(webmail["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-INPV-004 missing evidence markers: {missing}")
coverage = (pack / "COVERAGE.md").read_text()
if "OSMAP-WSTG-INPV-004" not in coverage or "WSTG-v42-INPV-10" not in coverage:
    raise SystemExit("COVERAGE.md missing webmail input-validation coverage")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_webmail_input_validation",
    "webmail_inpv10_subject_newline",
    "webmail_inpv10_recipient_newline",
    "webmail_inpv10_attachment_filename",
    "webmail_inpv10_dangerous_content_type",
    "write_webmail_input_validation_static_evidence",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing webmail input-validation marker {marker}")
doc = (repo / "docs" / "V3_WEBMAIL_INPUT_VALIDATION_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-INPV-004",
    "WSTG-v42-INPV-10",
    "subject newline injection",
    "recipient newline injection",
    "attachment filenames reject control characters",
    "application/octet-stream",
    "CSV injection remains not applicable",
]:
    if marker not in doc:
        raise SystemExit(f"webmail input-validation doc missing marker {marker}")
print("webmail input-validation WSTG mapping validated")
PY

echo "validating HTTP input-tampering WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
tampering = tests.get("OSMAP-WSTG-INPV-005")
if not tampering:
    raise SystemExit("OSMAP-WSTG-INPV-005 missing from WSTG mapping")
if tampering["wstg"] != ["WSTG-v42-INPV-03", "WSTG-v42-INPV-04"]:
    raise SystemExit("OSMAP-WSTG-INPV-005 must map to WSTG-v42-INPV-03 and WSTG-v42-INPV-04")
if tampering["requires_authenticated_coverage"] is not False or tampering["requires_totp"] is not False:
    raise SystemExit("OSMAP-WSTG-INPV-005 must remain unauthenticated")
required_evidence = {
    "http_inpv03_options_send.headers",
    "http_inpv03_put_login.headers",
    "http_inpv03_get_body_mailboxes.headers",
    "http_inpv03_post_mailboxes.headers",
    "http_inpv04_login_json_content_type.headers",
    "http_inpv04_send_json_content_type.headers",
    "http_inpv04_duplicate_query.headers",
    "http_inpv04_duplicate_login_field.headers",
    "http_inpv04_duplicate_send_field.headers",
    "http_input_tampering_static.txt",
}
missing = sorted(required_evidence - set(tampering["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-INPV-005 missing evidence markers: {missing}")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-INPV-005", "WSTG-v42-INPV-03", "WSTG-v42-INPV-04"]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing HTTP input-tampering marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_http_input_tampering",
    "http_inpv03_get_body_mailboxes",
    "http_inpv04_duplicate_query",
    "http_inpv04_duplicate_send_field",
    "write_http_input_tampering_static_evidence",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing HTTP input-tampering marker {marker}")
doc = (repo / "docs" / "V3_HTTP_INPUT_TAMPERING_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-INPV-005",
    "WSTG-v42-INPV-03",
    "WSTG-v42-INPV-04",
    "GET requests carrying a request body",
    "duplicate URL-encoded form fields",
]:
    if marker not in doc:
        raise SystemExit(f"HTTP input-tampering doc missing marker {marker}")
matrix = json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())
rows = {item["wstg_id"]: item for item in matrix["scenarios"]}
for wstg_id in ["WSTG-v42-INPV-03", "WSTG-v42-INPV-04"]:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-INPV-005" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-INPV-005")
print("HTTP input-tampering WSTG mapping validated")
PY

echo "validating HTTP host/smuggling WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
host = tests.get("OSMAP-WSTG-INPV-006")
if not host:
    raise SystemExit("OSMAP-WSTG-INPV-006 missing from WSTG mapping")
if host["wstg"] != ["WSTG-v42-INPV-15", "WSTG-v42-INPV-16", "WSTG-v42-INPV-17"]:
    raise SystemExit("OSMAP-WSTG-INPV-006 must map to WSTG-v42-INPV-15/16/17")
if host["requires_authenticated_coverage"] is not False or host["requires_totp"] is not False:
    raise SystemExit("OSMAP-WSTG-INPV-006 must remain unauthenticated")
required_evidence = {
    "http_inpv15_cl_te_smuggling.headers",
    "http_inpv15_duplicate_content_length.headers",
    "http_inpv15_encoded_crlf_target.headers",
    "http_inpv16_missing_host.headers",
    "http_inpv16_folded_header.headers",
    "http_inpv16_non_normalized_target.headers",
    "http_inpv17_duplicate_host.headers",
    "http_inpv17_malformed_host.headers",
    "http_inpv17_untrusted_host.headers",
    "http_host_smuggling_static.txt",
}
missing = sorted(required_evidence - set(host["evidence_produced"]))
if missing:
    raise SystemExit(f"OSMAP-WSTG-INPV-006 missing evidence markers: {missing}")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-INPV-006", "WSTG-v42-INPV-15", "WSTG-v42-INPV-16", "WSTG-v42-INPV-17"]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing HTTP host/smuggling marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "raw_http_request",
    "parse_raw_http_evidence",
    "test_http_host_and_smuggling_input",
    "http_inpv15_cl_te_smuggling",
    "http_inpv17_untrusted_host",
    "write_http_host_smuggling_static_evidence",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing HTTP host/smuggling marker {marker}")
doc = (repo / "docs" / "V3_HTTP_HOST_SMUGGLING_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-INPV-006",
    "WSTG-v42-INPV-15",
    "WSTG-v42-INPV-16",
    "WSTG-v42-INPV-17",
    "CL.TE request smuggling",
    "arbitrary untrusted `Host`",
]:
    if marker not in doc:
        raise SystemExit(f"HTTP host/smuggling doc missing marker {marker}")
matrix = json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())
rows = {item["wstg_id"]: item for item in matrix["scenarios"]}
for wstg_id in ["WSTG-v42-INPV-15", "WSTG-v42-INPV-16", "WSTG-v42-INPV-17"]:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-INPV-006" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-INPV-006")
print("HTTP host/smuggling WSTG mapping validated")
PY

echo "validating remaining injection applicability WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
applicability = tests.get("OSMAP-WSTG-INPV-007")
if not applicability:
    raise SystemExit("OSMAP-WSTG-INPV-007 missing from WSTG mapping")
expected_wstg = [
    "WSTG-v42-INPV-05",
    "WSTG-v42-INPV-06",
    "WSTG-v42-INPV-07",
    "WSTG-v42-INPV-08",
    "WSTG-v42-INPV-09",
    "WSTG-v42-INPV-11",
    "WSTG-v42-INPV-13",
    "WSTG-v42-INPV-14",
    "WSTG-v42-INPV-18",
    "WSTG-v42-INPV-19",
]
if applicability["wstg"] != expected_wstg:
    raise SystemExit("OSMAP-WSTG-INPV-007 must map the remaining Slice 4 injection applicability set")
if applicability["requires_authenticated_coverage"] is not False or applicability["requires_totp"] is not False:
    raise SystemExit("OSMAP-WSTG-INPV-007 must remain unauthenticated")
if set(applicability["evidence_produced"]) != {"injection_applicability_static.txt"}:
    raise SystemExit("OSMAP-WSTG-INPV-007 evidence set changed unexpectedly")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-INPV-007", *expected_wstg]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing injection applicability marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_injection_applicability_static",
    "write_injection_applicability_static_evidence",
    "no SQL database driver",
    "no outbound HTTP client",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing injection applicability marker {marker}")
doc = (repo / "docs" / "V3_INJECTION_APPLICABILITY_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-INPV-007",
    "no SQL database driver",
    "no LDAP client",
    "no XML parser",
    "no XPath engine",
    "no server-side template engine",
    "no outbound HTTP client",
]:
    if marker not in doc:
        raise SystemExit(f"injection applicability doc missing marker {marker}")
matrix = json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())
rows = {item["wstg_id"]: item for item in matrix["scenarios"]}
for wstg_id in expected_wstg:
    row = rows[wstg_id]
    if row["disposition"] != "not_applicable" or "OSMAP-WSTG-INPV-007" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be not_applicable with OSMAP-WSTG-INPV-007 evidence")
print("remaining injection applicability WSTG mapping validated")
PY

echo "validating weak cryptography WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
transport = tests.get("OSMAP-WSTG-CRYP-001")
primitive = tests.get("OSMAP-WSTG-CRYP-002")
if not transport or not primitive:
    raise SystemExit("Slice 5 CRYP mappings missing")
if transport["wstg"] != ["WSTG-v42-CRYP-01", "WSTG-v42-CRYP-03"]:
    raise SystemExit("OSMAP-WSTG-CRYP-001 must map CRYP-01 and CRYP-03")
if primitive["wstg"] != ["WSTG-v42-CRYP-02", "WSTG-v42-CRYP-04"]:
    raise SystemExit("OSMAP-WSTG-CRYP-002 must map CRYP-02 and CRYP-04")
if transport["requires_authenticated_coverage"] or transport["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-CRYP-001 must remain unauthenticated")
if primitive["requires_authenticated_coverage"] or primitive["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-CRYP-002 must remain unauthenticated")
expected_transport_evidence = {
    "crypto_https_login.headers",
    "crypto_cleartext_login.headers",
    "crypto_transport_static.txt",
    "crypto_tls_policy_guard.txt",
    "crypto_tls_standard_report.json",
    "crypto_tls_standard_validate.txt",
}
if set(transport["evidence_produced"]) != expected_transport_evidence:
    raise SystemExit("OSMAP-WSTG-CRYP-001 evidence set changed unexpectedly")
if set(primitive["evidence_produced"]) != {"crypto_primitive_applicability_static.txt"}:
    raise SystemExit("OSMAP-WSTG-CRYP-002 evidence set changed unexpectedly")
coverage = (pack / "COVERAGE.md").read_text()
for marker in [
    "OSMAP-WSTG-CRYP-001",
    "OSMAP-WSTG-CRYP-002",
    "WSTG-v42-CRYP-01",
    "WSTG-v42-CRYP-02",
    "WSTG-v42-CRYP-03",
    "WSTG-v42-CRYP-04",
]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing CRYP marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_crypto_transport_security",
    "write_crypto_tls_standard_evidence",
    "test_crypto_primitive_applicability_static",
    "no padding oracle surface",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing CRYP marker {marker}")
doc = (repo / "docs" / "V3_CRYPTO_TRANSPORT_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-CRYP-001",
    "OSMAP-WSTG-CRYP-002",
    "Strict-Transport-Security",
    "no application encryption/decryption primitive",
    "no CBC decryptor",
    "no padding oracle surface",
    "no custom reversible encryption",
]:
    if marker not in doc:
        raise SystemExit(f"crypto evidence doc missing marker {marker}")
matrix = json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())
rows = {item["wstg_id"]: item for item in matrix["scenarios"]}
for wstg_id in ["WSTG-v42-CRYP-01", "WSTG-v42-CRYP-03"]:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-CRYP-001" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-CRYP-001")
for wstg_id in ["WSTG-v42-CRYP-02", "WSTG-v42-CRYP-04"]:
    row = rows[wstg_id]
    if row["disposition"] != "not_applicable" or "OSMAP-WSTG-CRYP-002" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be not_applicable with OSMAP-WSTG-CRYP-002 evidence")
print("weak cryptography WSTG mapping validated")
PY

echo "validating form route and GraphQL applicability WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
busl = tests.get("OSMAP-WSTG-BUSL-005")
apit = tests.get("OSMAP-WSTG-APIT-001")
if not busl or not apit:
    raise SystemExit("Slice 6 form route/APIT mappings missing")
expected_busl = [
    "WSTG-v42-BUSL-01",
    "WSTG-v42-BUSL-02",
    "WSTG-v42-BUSL-03",
    "WSTG-v42-BUSL-05",
    "WSTG-v42-BUSL-06",
    "WSTG-v42-BUSL-07",
]
if busl["wstg"] != expected_busl:
    raise SystemExit("OSMAP-WSTG-BUSL-005 must map the Slice 6 BUSL set")
if apit["wstg"] != ["WSTG-v42-APIT-01"]:
    raise SystemExit("OSMAP-WSTG-APIT-001 must map APIT-01")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-BUSL-005", "OSMAP-WSTG-APIT-001", *expected_busl, "WSTG-v42-APIT-01"]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing Slice 6 marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in ["test_form_route_state_transitions_static", "test_graphql_applicability_static", "browser form-backed routes"]:
    if marker not in runner:
        raise SystemExit(f"runner missing Slice 6 marker {marker}")
doc = (repo / "docs" / "V3_FORM_ROUTE_STATE_TRANSITIONS.md").read_text()
for marker in ["no GraphQL endpoint", "no GraphQL dependency", "browser form routes rather than API routes"]:
    if marker not in doc:
        raise SystemExit(f"Slice 6 doc missing marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected_busl:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-BUSL-005" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-BUSL-005")
row = rows["WSTG-v42-APIT-01"]
if row["disposition"] != "not_applicable" or "OSMAP-WSTG-APIT-001" not in row["evidence_reference"]:
    raise SystemExit("APIT-01 must be not_applicable with OSMAP-WSTG-APIT-001 evidence")
print("form route and GraphQL applicability WSTG mapping validated")
PY

echo "validating client-side browser WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
client = tests.get("OSMAP-WSTG-CLNT-003")
if not client:
    raise SystemExit("OSMAP-WSTG-CLNT-003 missing")
expected = [
    "WSTG-v42-CLNT-02",
    "WSTG-v42-CLNT-03",
    "WSTG-v42-CLNT-04",
    "WSTG-v42-CLNT-05",
    "WSTG-v42-CLNT-06",
    "WSTG-v42-CLNT-08",
    "WSTG-v42-CLNT-10",
    "WSTG-v42-CLNT-11",
    "WSTG-v42-CLNT-12",
    "WSTG-v42-CLNT-13",
]
if client["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-CLNT-003 must map remaining Slice 8 CLNT rows")
if client["requires_authenticated_coverage"] or client["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-CLNT-003 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-CLNT-003", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing client-side marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in ["test_client_side_applicability_static", "no WebSocket route", "no browser storage use", "UrlRelative::Deny"]:
    if marker not in runner:
        raise SystemExit(f"runner missing client-side marker {marker}")
doc = (repo / "docs" / "V3_CLIENT_SIDE_BROWSER_SECURITY.md").read_text()
for marker in ["no client-side scripting dependency", "no WebSocket route", "no browser storage use", "no web messaging surface"]:
    if marker not in doc:
        raise SystemExit(f"client-side doc missing marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if row["disposition"] != "not_applicable" or "OSMAP-WSTG-CLNT-003" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be not_applicable with OSMAP-WSTG-CLNT-003 evidence")
print("client-side browser WSTG mapping validated")
PY

echo "validating error handling and information disclosure WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
info = tests.get("OSMAP-WSTG-INFO-003")
if not info:
    raise SystemExit("OSMAP-WSTG-INFO-003 missing")
expected = [
    "WSTG-v42-ERRH-02",
    "WSTG-v42-INFO-06",
    "WSTG-v42-INFO-07",
    "WSTG-v42-INFO-10",
]
if info["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-INFO-003 must map ERRH-02 and INFO-06/07/10")
if info["requires_authenticated_coverage"] or info["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-INFO-003 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-INFO-003", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing Slice 9 marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_error_and_route_inventory",
    "error_route_inventory_static.txt",
    "stack traces are not browser-visible",
    "http_route_not_found",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing Slice 9 marker {marker}")
doc = (repo / "docs" / "V3_ERROR_INFO_DISCLOSURE_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-INFO-003",
    "stack traces are not browser-visible",
    "Route And Entry-Point Inventory",
    "Architecture Inventory",
]:
    if marker not in doc:
        raise SystemExit(f"Slice 9 doc missing marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-INFO-003" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-INFO-003")
print("error handling and information disclosure WSTG mapping validated")
PY

echo "validating public reconnaissance and fingerprinting WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
recon = tests.get("OSMAP-WSTG-INFO-004")
if not recon:
    raise SystemExit("OSMAP-WSTG-INFO-004 missing")
expected = [
    "WSTG-v42-INFO-01",
    "WSTG-v42-INFO-04",
    "WSTG-v42-INFO-08",
    "WSTG-v42-INFO-09",
]
if recon["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-INFO-004 must map remaining Slice 9 INFO rows")
if recon["requires_authenticated_coverage"] or recon["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-INFO-004 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-INFO-004", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing public reconnaissance marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_public_reconnaissance_fingerprinting",
    "public_recon_fingerprinting_static.txt",
    "bounded public reconnaissance",
    "no X-Powered-By",
    "no secondary webmail app",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing public reconnaissance marker {marker}")
doc = (repo / "docs" / "V3_ERROR_INFO_DISCLOSURE_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-INFO-004",
    "Public Reconnaissance And Fingerprinting",
    "Search engine discovery reconnaissance",
    "no framework version banner",
]:
    if marker not in doc:
        raise SystemExit(f"Slice 9 doc missing public reconnaissance marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-INFO-004" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-INFO-004")
print("public reconnaissance and fingerprinting WSTG mapping validated")
PY

echo "validating sensitive extension and backup exposure WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
conf = tests.get("OSMAP-WSTG-CONF-008")
if not conf:
    raise SystemExit("OSMAP-WSTG-CONF-008 missing")
expected = ["WSTG-v42-CONF-03", "WSTG-v42-CONF-04"]
if conf["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-CONF-008 must map CONF-03 and CONF-04")
if conf["requires_authenticated_coverage"] or conf["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-CONF-008 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-CONF-008", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing sensitive extension marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_sensitive_extension_and_backup_exposure",
    "sensitive_extension_backup_static.txt",
    "backup and unreferenced file exposure",
    "no public static repository root",
    "no source archive exposure",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing sensitive extension marker {marker}")
doc = (repo / "docs" / "V3_CONFIG_DEPLOYMENT_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-CONF-008",
    "sensitive extension handling",
    "backup and unreferenced file exposure",
    "no public backup directory",
]:
    if marker not in doc:
        raise SystemExit(f"Slice 10 doc missing marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-CONF-008" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-CONF-008")
print("sensitive extension and backup exposure WSTG mapping validated")
PY

echo "validating RIA and cloud storage applicability WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
conf = tests.get("OSMAP-WSTG-CONF-009")
if not conf:
    raise SystemExit("OSMAP-WSTG-CONF-009 missing")
expected = ["WSTG-v42-CONF-08", "WSTG-v42-CONF-11"]
if conf["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-CONF-009 must map CONF-08 and CONF-11")
if conf["requires_authenticated_coverage"] or conf["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-CONF-009 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-CONF-009", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing RIA/cloud marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_ria_cloud_storage_applicability",
    "ria_cloud_storage_static.txt",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "no cloud storage dependency",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing RIA/cloud marker {marker}")
doc = (repo / "docs" / "V3_CONFIG_DEPLOYMENT_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-CONF-009",
    "no public RIA cross-domain policy",
    "no cloud object storage surface",
    "no cloud storage dependency",
]:
    if marker not in doc:
        raise SystemExit(f"Slice 10 doc missing RIA/cloud marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if row["disposition"] != "not_applicable" or "OSMAP-WSTG-CONF-009" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be not-applicable with OSMAP-WSTG-CONF-009 evidence")
print("RIA and cloud storage applicability WSTG mapping validated")
PY

echo "validating file-permission and subdomain takeover WSTG mapping"
python3 - "$pack_dir" <<'PY'
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
repo = pack.parents[1]
mapping = json.loads((pack / "wstg-asvs-mapping.json").read_text())
tests = {item["test_id"]: item for item in mapping["tests"]}
conf = tests.get("OSMAP-WSTG-CONF-010")
if not conf:
    raise SystemExit("OSMAP-WSTG-CONF-010 missing")
expected = ["WSTG-v42-CONF-09", "WSTG-v42-CONF-10"]
if conf["wstg"] != expected:
    raise SystemExit("OSMAP-WSTG-CONF-010 must map CONF-09 and CONF-10")
if conf["requires_authenticated_coverage"] or conf["requires_totp"]:
    raise SystemExit("OSMAP-WSTG-CONF-010 must remain unauthenticated")
coverage = (pack / "COVERAGE.md").read_text()
for marker in ["OSMAP-WSTG-CONF-010", *expected]:
    if marker not in coverage:
        raise SystemExit(f"COVERAGE.md missing file-permission/subdomain marker {marker}")
runner = (pack / "run-wstg-pack.py").read_text()
for marker in [
    "test_file_permissions_and_subdomain_takeover",
    "host_file_permissions.txt",
    "subdomain_takeover_dns.txt",
    "file_permission_subdomain_static.txt",
    "mail.blackbagsecurity.com has no CNAME record",
    "no dangling takeover CNAME",
]:
    if marker not in runner:
        raise SystemExit(f"runner missing file-permission/subdomain marker {marker}")
doc = (repo / "docs" / "V3_CONFIG_DEPLOYMENT_EVIDENCE.md").read_text()
for marker in [
    "OSMAP-WSTG-CONF-010",
    "file-permission evidence",
    "Subdomain Takeover",
    "no dangling takeover CNAME",
]:
    if marker not in doc:
        raise SystemExit(f"Slice 10 doc missing file-permission/subdomain marker {marker}")
rows = {item["wstg_id"]: item for item in json.loads((pack / "wstg-scenario-matrix.v42.json").read_text())["scenarios"]}
for wstg_id in expected:
    row = rows[wstg_id]
    if row["disposition"] != "automated" or "OSMAP-WSTG-CONF-010" not in row["evidence_reference"]:
        raise SystemExit(f"{wstg_id} must be automated by OSMAP-WSTG-CONF-010")
print("file-permission and subdomain takeover WSTG mapping validated")
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

echo "validating webmail input-validation route skips without credentials"
if ! python3 "$pack_dir/run-wstg-pack.py" \
	--unauthenticated \
	--test-id OSMAP-WSTG-INPV-004 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root/webmail-input-validation-skip" >/dev/null 2>&1; then
	echo "expected credential-gated webmail input-validation route test to skip cleanly without credentials" >&2
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
