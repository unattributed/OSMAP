#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

: "${TMPDIR:=/tmp/osmap-tmp}"
: "${CARGO_HOME:=/tmp/osmap-cargo-home}"
: "${CARGO_TARGET_DIR:=/tmp/osmap-target}"
: "${OSMAP_RELEASE_EVIDENCE_DIR:=$repo_root/maint/live}"
: "${OSMAP_V4_ASSURANCE_CORPUS_DIR:=tests/testdata/hostile-mail-corpus}"
: "${OSMAP_V4_ASSURANCE_REPORT:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-v4-hostile-assurance-report.json}"
: "${OSMAP_V4_ASSURANCE_ARCHIVE:=$OSMAP_RELEASE_EVIDENCE_DIR/osmap-v4-hostile-assurance-evidence.tar.gz}"

mkdir -p "$TMPDIR" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$OSMAP_RELEASE_EVIDENCE_DIR"
export TMPDIR CARGO_HOME CARGO_TARGET_DIR

assessed_ref=${OSMAP_V4_ASSURANCE_ASSESSED_REF:-$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')}
generated_at=${OSMAP_V4_ASSURANCE_GENERATED_AT:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}
export OSMAP_V4_ASSURANCE_REPORT OSMAP_V4_ASSURANCE_ASSESSED_REF="$assessed_ref" OSMAP_V4_ASSURANCE_GENERATED_AT="$generated_at"

if ! command -v cargo >/dev/null 2>&1; then
	echo "error: cargo is required for the V4 hostile-content assurance gate" >&2
	exit 1
fi

if [ ! -d "$OSMAP_V4_ASSURANCE_CORPUS_DIR" ]; then
	echo "error: hostile mail corpus directory is missing: $OSMAP_V4_ASSURANCE_CORPUS_DIR" >&2
	exit 1
fi

python3 - "$OSMAP_V4_ASSURANCE_CORPUS_DIR" <<'PY'
import json
import sys
from pathlib import Path

corpus = Path(sys.argv[1])
manifest_path = corpus / "MANIFEST.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

required_categories = set(manifest.get("required_categories", []))
fixtures = manifest.get("fixtures", [])
errors = []
covered_categories = set()

expected_categories = {
    "hostile HTML",
    "CSS abuse",
    "tracking attempts",
    "CID abuse",
    "unicode deception",
    "suspicious links",
    "malformed headers",
    "nested MIME structures",
    "suspicious charsets",
    "spoofed filenames",
    "attachment deception",
}

if required_categories != expected_categories:
    errors.append("manifest required_categories does not match V4.1 required category set")
if not fixtures:
    errors.append("manifest contains no fixtures")

for fixture in fixtures:
    eml = corpus / fixture
    metadata_path = eml.with_suffix(".json")
    if not eml.is_file():
        errors.append(f"missing fixture: {eml}")
        continue
    if not metadata_path.is_file():
        errors.append(f"missing metadata: {metadata_path}")
        continue
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"metadata is not valid JSON: {metadata_path}: {exc}")
        continue

    for field in [
        "fixture_identifier",
        "category",
        "expected_outcome",
        "security_objective",
        "release_coverage_mapping",
    ]:
        if field not in metadata or not metadata[field]:
            errors.append(f"{metadata_path} missing required metadata field {field}")

    categories = metadata.get("category", [])
    if isinstance(categories, str):
        categories = [categories]
    if not isinstance(categories, list):
        errors.append(f"{metadata_path} category must be a string or list")
        categories = []
    covered_categories.update(categories)

    mapping = metadata.get("release_coverage_mapping", [])
    if isinstance(mapping, str):
        mapping = [mapping]
    if "V4.1 hostile corpus" not in mapping:
        errors.append(f"{metadata_path} does not map to V4.1 hostile corpus")

missing = sorted(required_categories - covered_categories)
if missing:
    errors.append(f"fixture coverage is incomplete; missing categories: {', '.join(missing)}")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)

print(f"validated {len(fixtures)} hostile corpus fixtures covering {len(covered_categories)} categories")
PY

rm -f "$OSMAP_V4_ASSURANCE_REPORT"

echo "==> cargo test --test v4_hostile_assurance"
cargo test --test v4_hostile_assurance -- --nocapture

if [ ! -s "$OSMAP_V4_ASSURANCE_REPORT" ]; then
	echo "error: V4 hostile-content assurance report was not generated: $OSMAP_V4_ASSURANCE_REPORT" >&2
	exit 1
fi

python3 - "$OSMAP_V4_ASSURANCE_REPORT" "$assessed_ref" <<'PY'
import json
import re
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
assessed_ref = sys.argv[2]
report_text = report_path.read_text(encoding="utf-8")
report = json.loads(report_text)
errors = []

if report.get("schema") != "osmap-v4-hostile-assurance-report-v1":
    errors.append("unexpected report schema")
if report.get("status") != "passed":
    errors.append("assurance report status is not passed")
if report.get("assessed_ref") != assessed_ref:
    errors.append("assurance report assessed_ref does not match the gate input")
if report.get("corpus_root") != "tests/testdata/hostile-mail-corpus":
    errors.append("assurance report corpus_root is unexpected")

required_components = {
    "hostile_corpus_metadata",
    "browser_rendered_negative_assertions",
    "mime_parser_robustness",
    "attachment_deception_handling",
    "browser_isolation_verification",
}
components = report.get("components", [])
component_status = {item.get("component"): item.get("status") for item in components}
missing = sorted(required_components - set(component_status))
if missing:
    errors.append(f"missing assurance components: {', '.join(missing)}")
for component, status in sorted(component_status.items()):
    if status != "passed":
        errors.append(f"component {component} did not pass: {status}")

network_assertions = report.get("network_assertions", {})
for key in [
    "remote_fetches",
    "beacon_requests",
    "websocket_requests",
    "service_worker_registrations",
]:
    if network_assertions.get(key) != 0:
        errors.append(f"network assertion {key} expected zero")

route_observations = report.get("route_backed_observations", {})
for key in [
    "rendered_message_routes",
    "attachment_download_routes",
    "dom_assertions",
]:
    if not isinstance(route_observations.get(key), int) or route_observations.get(key) <= 0:
        errors.append(f"route-backed observation {key} is missing or invalid")
for key in [
    "auto_fetch_surfaces",
    "unsafe_browser_api_references",
]:
    if route_observations.get(key) != 0:
        errors.append(f"route-backed observation {key} expected zero")

resources = report.get("resource_usage_observations", {})
for key in [
    "mime_max_depth",
    "mime_max_parts",
    "mime_header_count_max",
    "attachment_download_max_bytes",
]:
    if not isinstance(resources.get(key), int) or resources.get(key) <= 0:
        errors.append(f"resource observation {key} is missing or invalid")

for forbidden in [
    'session_id="',
    "osmap_session=",
    "csrf_token=",
    "totp seed",
    "password=",
    "private message body",
    "private attachment",
    "provider secret",
    "host secret",
]:
    if re.search(re.escape(forbidden), report_text, flags=re.IGNORECASE):
        errors.append(f"forbidden evidence content present: {forbidden}")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
PY

report_for_archive=$OSMAP_V4_ASSURANCE_REPORT
case "$report_for_archive" in
	"$repo_root"/*) report_for_archive=${report_for_archive#"$repo_root"/} ;;
esac

tar -czf "$OSMAP_V4_ASSURANCE_ARCHIVE" \
	"$report_for_archive" \
	"$OSMAP_V4_ASSURANCE_CORPUS_DIR/README.md" \
	"$OSMAP_V4_ASSURANCE_CORPUS_DIR/MANIFEST.json" \
	"$OSMAP_V4_ASSURANCE_CORPUS_DIR/html" \
	"$OSMAP_V4_ASSURANCE_CORPUS_DIR/mime" \
	"$OSMAP_V4_ASSURANCE_CORPUS_DIR/unicode" \
	"$OSMAP_V4_ASSURANCE_CORPUS_DIR/attachments"

if [ ! -s "$OSMAP_V4_ASSURANCE_ARCHIVE" ]; then
	echo "error: V4 hostile-content assurance archive was not generated: $OSMAP_V4_ASSURANCE_ARCHIVE" >&2
	exit 1
fi

echo "V4 hostile-content assurance gate passed"
echo "report=$OSMAP_V4_ASSURANCE_REPORT"
echo "archive=$OSMAP_V4_ASSURANCE_ARCHIVE"
