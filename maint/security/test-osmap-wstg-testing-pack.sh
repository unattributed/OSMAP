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
    "OSMAP_RATE_LIMIT_DELAY_SECONDS=",
    "OSMAP_ALLOW_AUTHENTICATED_TESTS=false",
]:
    if key not in env_text:
        raise SystemExit(f".env.example missing {key}")

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

echo "validating authenticated draft route skips without credentials"
if ! python3 "$pack_dir/run-wstg-pack.py" \
	--unauthenticated \
	--test-id OSMAP-WSTG-BUSL-002 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root" >/dev/null 2>&1; then
	echo "expected credential-gated draft route test to skip cleanly without credentials" >&2
	exit 1
fi

echo "validating WSTG release mode fails on skipped authenticated coverage"
if python3 "$pack_dir/run-wstg-pack.py" \
	--release \
	--test-id OSMAP-WSTG-ATHN-004 \
	--base-url http://127.0.0.1:9 \
	--host 127.0.0.1 \
	--output-dir "$tmp_root" >/dev/null 2>&1; then
	echo "expected WSTG release mode to fail when authenticated coverage is skipped" >&2
	exit 1
fi

echo "WSTG testing pack validation passed"
