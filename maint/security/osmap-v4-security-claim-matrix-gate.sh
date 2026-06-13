#!/bin/sh
set -eu

repo_root=${OSMAP_V4_CLAIM_MATRIX_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

: "${OSMAP_V4_CLAIM_MATRIX_DOC:=docs/V4_SECURITY_CLAIM_MATRIX.md}"
: "${OSMAP_V4_CLAIM_MATRIX_REPORT:=maint/live/osmap-v4-hostile-assurance-report.json}"
: "${OSMAP_V4_CLAIM_MATRIX_ARCHIVE:=maint/live/osmap-v4-hostile-assurance-evidence.tar.gz}"

for path in \
	"$OSMAP_V4_CLAIM_MATRIX_DOC" \
	"$OSMAP_V4_CLAIM_MATRIX_REPORT" \
	"$OSMAP_V4_CLAIM_MATRIX_ARCHIVE"
do
	if [ ! -s "$path" ]; then
		echo "error: missing V4 security claim matrix input: $path" >&2
		exit 1
	fi
done

python3 - \
	"$repo_root" \
	"$OSMAP_V4_CLAIM_MATRIX_DOC" \
	"$OSMAP_V4_CLAIM_MATRIX_REPORT" \
	"$OSMAP_V4_CLAIM_MATRIX_ARCHIVE" <<'PY'
import json
import re
import sys
import tarfile
from pathlib import Path

repo_root = Path(sys.argv[1])
matrix_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
archive_path = Path(sys.argv[4])

errors = []
matrix = matrix_path.read_text(encoding="utf-8")
report = json.loads(report_path.read_text(encoding="utf-8"))

required_claims = {
    "Hostile HTML cannot execute in the message view": "browser_rendered_negative_assertions",
    "Remote content does not load automatically from rendered mail": "browser_rendered_negative_assertions",
    "MIME parser behavior is bounded under malformed input": "mime_parser_robustness",
    "Attachment deception is contained as download-only behavior": "attachment_deception_handling",
    "Browser isolation headers preserve the mail/browser boundary": "browser_isolation_verification",
    "V4 assurance evidence is release-gated, tuple-checked, claim-matrix-checked, and archived": "hostile_corpus_metadata",
}
required_columns = [
    "Claim",
    "Implementation",
    "Automated test",
    "Validation evidence",
    "Residual risk",
    "Limitation",
    "Non-goal",
]
required_non_goals = [
    "rich HTML feature parity",
    "remote image loading",
    "full MIME client compatibility",
    "attachment preview safety",
    "service workers",
    "silent tuple drift",
]
forbidden_overclaims = [
    "makes malicious links safe",
    "makes downloaded attachments safe",
    "malware scanning",
    "URL reputation",
    "safely previews arbitrary active documents",
    "complete Roundcube feature parity",
]


def split_table_row(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


rows = []
in_table = False
for line in matrix.splitlines():
    if line.startswith("| Claim | Implementation |"):
        in_table = True
        continue
    if not in_table:
        continue
    if line.startswith("| ---"):
        continue
    if not line.startswith("|"):
        if rows:
            break
        continue
    cells = split_table_row(line)
    if len(cells) != len(required_columns):
        errors.append(f"claim matrix row has {len(cells)} columns, expected {len(required_columns)}: {line}")
        continue
    rows.append(dict(zip(required_columns, cells)))

if not rows:
    errors.append("claim matrix table was not found")

claims = {row.get("Claim", ""): row for row in rows}
for claim, component in required_claims.items():
    if claim not in claims:
        errors.append(f"claim matrix missing required claim: {claim}")
        continue
    row = claims[claim]
    for column in required_columns:
        value = row.get(column, "").strip()
        if not value:
            errors.append(f"claim {claim!r} has empty {column!r} cell")
        if re.search(r"\b(TBD|TODO|unknown|n/a)\b", value, flags=re.IGNORECASE):
            errors.append(f"claim {claim!r} has non-auditable {column!r} cell: {value!r}")
    if "osmap-v4-hostile-assurance-report.json" not in row["Validation evidence"]:
        errors.append(f"claim {claim!r} does not map to V4 assurance report evidence")

all_text = matrix
for non_goal in required_non_goals:
    if non_goal not in all_text:
        errors.append(f"claim matrix missing required non-goal language: {non_goal}")
for overclaim in forbidden_overclaims:
    if overclaim in all_text:
        errors.append(f"claim matrix contains forbidden overclaim: {overclaim}")

path_tokens = set()
for row in rows:
    for column in ["Implementation", "Automated test", "Validation evidence"]:
        for token in re.findall(r"`([^`]+)`", row[column]):
            if "/" in token and not any(ch.isspace() for ch in token):
                path_tokens.add(token.rstrip(".,;:"))

for token in sorted(path_tokens):
    path = repo_root / token
    if not path.exists():
        errors.append(f"claim matrix references missing path: {token}")

if report.get("schema") != "osmap-v4-hostile-assurance-report-v1":
    errors.append("V4 hostile assurance report schema is unexpected")
if report.get("status") != "passed":
    errors.append("V4 hostile assurance report status is not passed")
release_gate = report.get("release_gate")
if release_gate not in {True, "maint/security/osmap-v4-hostile-assurance-gate.sh"}:
    errors.append("V4 hostile assurance report release_gate is not the V4 assurance gate")

components = {
    item.get("component"): item
    for item in report.get("components", [])
    if isinstance(item, dict)
}
for claim, component in required_claims.items():
    item = components.get(component)
    if not item:
        errors.append(f"V4 hostile assurance report missing component {component!r} for claim {claim!r}")
    elif item.get("status") != "passed":
        errors.append(f"V4 hostile assurance report component {component!r} is not passed")

network = report.get("network_assertions", {})
for key in [
    "remote_fetches",
    "beacon_requests",
    "websocket_requests",
    "service_worker_registrations",
]:
    if network.get(key) != 0:
        errors.append(f"V4 hostile assurance network assertion {key} expected 0, found {network.get(key)!r}")

route = report.get("route_backed_observations", {})
if route.get("rendered_message_routes", 0) < 1:
    errors.append("V4 hostile assurance report lacks rendered message route observations")
if route.get("attachment_download_routes", 0) < 1:
    errors.append("V4 hostile assurance report lacks attachment route observations")
if route.get("auto_fetch_surfaces") != 0:
    errors.append("V4 hostile assurance route observations found auto-fetch surfaces")
if route.get("unsafe_browser_api_references") != 0:
    errors.append("V4 hostile assurance route observations found unsafe browser API references")

resources = report.get("resource_usage_observations", {})
for key in ["mime_max_depth", "mime_max_parts", "mime_header_count_max", "attachment_download_max_bytes"]:
    value = resources.get(key)
    if not isinstance(value, int) or value <= 0:
        errors.append(f"V4 hostile assurance resource observation {key} is not a positive integer")

try:
    with tarfile.open(archive_path, "r:gz") as archive:
        names = {
            member.name
            for member in archive.getmembers()
            if member.isfile()
        }
except Exception as exc:
    errors.append(f"could not inspect V4 hostile assurance archive: {exc}")
else:
    required_suffixes = [
        "osmap-v4-hostile-assurance-report.json",
        "tests/testdata/hostile-mail-corpus/MANIFEST.json",
        "tests/testdata/hostile-mail-corpus/html/hostile_html_active_content.eml",
        "tests/testdata/hostile-mail-corpus/mime/deep_nested_mime.eml",
        "tests/testdata/hostile-mail-corpus/attachments/spoofed_double_extension.eml",
    ]
    for suffix in required_suffixes:
        if not any(name.endswith(suffix) for name in names):
            errors.append(f"V4 hostile assurance archive missing {suffix}")

if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)

print("V4 security claim matrix gate passed")
print(f"claims={len(rows)}")
print(f"report={report_path}")
print(f"archive={archive_path}")
PY
