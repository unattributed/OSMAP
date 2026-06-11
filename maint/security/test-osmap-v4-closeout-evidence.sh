#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

closeout="${repo_root}/docs/V4_CLOSEOUT_EVIDENCE.md"
roadmap="${repo_root}/docs/V4_ROADMAP.md"
mime_evidence="${repo_root}/docs/V4_MIME_AMBIGUITY_EVIDENCE.md"
v4_report="${repo_root}/maint/live/latest-host-v4-hostile-content-report.txt"
v3_summary_md="${repo_root}/maint/live/osmap-v3-release-evidence-summary.md"
v3_summary_json="${repo_root}/maint/live/osmap-v3-release-evidence-summary.json"
v3_archive="${repo_root}/maint/live/osmap-v3-release-evidence.tar.gz"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "missing required V4 closeout evidence file: ${path#$repo_root/}" >&2
		exit 1
	fi
}

require_file "$closeout"
require_file "$roadmap"
require_file "$mime_evidence"
require_file "$v4_report"
require_file "$v3_summary_md"
require_file "$v3_summary_json"
require_file "$v3_archive"

python3 - "$repo_root" "$closeout" "$roadmap" "$mime_evidence" "$v4_report" "$v3_summary_md" "$v3_summary_json" <<'PY'
import json
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
closeout_path = Path(sys.argv[2])
roadmap_path = Path(sys.argv[3])
mime_evidence_path = Path(sys.argv[4])
v4_report_path = Path(sys.argv[5])
v3_summary_md_path = Path(sys.argv[6])
v3_summary_json_path = Path(sys.argv[7])

closeout = closeout_path.read_text(encoding="utf-8")
roadmap = roadmap_path.read_text(encoding="utf-8")
mime_evidence = mime_evidence_path.read_text(encoding="utf-8")
v4_report = v4_report_path.read_text(encoding="utf-8")
v3_summary_md = v3_summary_md_path.read_text(encoding="utf-8")
v3_summary = json.loads(v3_summary_json_path.read_text(encoding="utf-8"))

errors = []

match = re.search(r"\| Assessed code commit \| `([0-9a-f]{7,40})` \|", closeout)
if not match:
    errors.append("V4 closeout evidence does not name an assessed code commit")
    assessed = ""
else:
    assessed = match.group(1)

def parse_key_values(text):
    values = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values

v4_values = parse_key_values(v4_report)
v4_required = {
    "commit": assessed,
    "build_result": "passed",
    "helper_runtime_result": "passed",
    "browser_runtime_result": "passed",
    "hostile_html_message_view_status": "HTTP/1.1 200 OK",
    "hostile_html_sanitized_mode": "present",
    "hostile_html_destination_disclosure_css": "present",
    "hostile_html_javascript_scheme": "absent",
    "hostile_html_data_scheme": "absent",
    "hostile_html_cid_scheme": "absent",
    "hostile_html_relative_url": "absent",
    "hostile_html_protocol_relative_url": "absent",
    "hostile_html_img_payload": "absent",
    "hostile_html_body_marker_audit_leakage": "absent",
    "html_attachment_download_forced_download_octet_stream_nosniff_corp": "present",
    "svg_attachment_download_forced_download_octet_stream_nosniff_corp": "present",
    "script_attachment_download_forced_download_octet_stream_nosniff_corp": "present",
    "html_attachment_download_forced_download_octet_stream_nosniff_corp_body_marker_audit_leakage": "absent",
    "svg_attachment_download_forced_download_octet_stream_nosniff_corp_body_marker_audit_leakage": "absent",
    "script_attachment_download_forced_download_octet_stream_nosniff_corp_body_marker_audit_leakage": "absent",
    "result": "v4_hostile_content_live_proof_passed",
}

for key, expected in v4_required.items():
    actual = v4_values.get(key)
    if actual != expected:
        errors.append(f"V4 report {key} expected {expected!r}, found {actual!r}")

secret_review = v4_values.get("secret_review", "")
for required_text in [
    "No password",
    "TOTP material",
    "session cookie",
    "CSRF token",
    "private message body",
    "attachment body",
    "provider secret",
    "host secret",
]:
    if required_text not in secret_review:
        errors.append(f"V4 report secret review missing {required_text!r}")

assessed_ref = v3_summary.get("assessed_ref", "")
if assessed and not assessed_ref.startswith(assessed):
    errors.append(
        f"V3 carry-forward assessed ref {assessed_ref!r} does not match V4 assessed commit {assessed!r}"
    )

if v3_summary.get("security_profile") != "release":
    errors.append("V3 carry-forward summary is not release profile")
if v3_summary.get("skipped_checks") != []:
    errors.append("V3 carry-forward summary contains skipped checks")

for label, value in {
    "cargo build": v3_summary.get("cargo", {}).get("build"),
    "cargo test": v3_summary.get("cargo", {}).get("test"),
    "cargo clippy": v3_summary.get("cargo", {}).get("clippy"),
    "cargo fmt_check": v3_summary.get("cargo", {}).get("fmt_check"),
    "supply_chain": v3_summary.get("supply_chain"),
    "dependency_inventory_status": v3_summary.get("dependency_inventory_status"),
    "wstg_status": v3_summary.get("wstg_status"),
    "authenticated_wstg_status": v3_summary.get("authenticated_wstg_status"),
    "tls_cbc_status": v3_summary.get("tls_cbc_status"),
    "tls_standard_status": v3_summary.get("tls_standard_status"),
    "resource_timeout_status": v3_summary.get("resource_timeout_status"),
    "helper_boundary_status": v3_summary.get("helper_boundary_status"),
    "v3_mime_html_proof_status": v3_summary.get("v3_mime_html_proof_status"),
    "v3_pilot_rehearsal_status": v3_summary.get("v3_pilot_rehearsal_status"),
    "sanitized_evidence_archive_status": v3_summary.get("sanitized_evidence_archive_status"),
}.items():
    if value != "passed":
        errors.append(f"V3 carry-forward {label} expected 'passed', found {value!r}")

for pattern, source_name, source in [
    (r"The V4 hostile-content closeout evidence bundle is assembled", "closeout", closeout),
    (r"Residual-Risk Statement", "closeout", closeout),
    (r"does\s+not make attacker-controlled email globally safe", "closeout", closeout),
    (r"files may still be malicious after a user\s+opens them", "closeout", closeout),
    (r"V4 hostile-content closeout evidence bundle is assembled", "roadmap", roadmap),
    (r"MIME ambiguity and metadata breadth", "MIME evidence", mime_evidence),
    (r"product-code regression tests", "MIME evidence", mime_evidence),
]:
    if not re.search(pattern, source):
        errors.append(f"{source_name} missing required pattern: {pattern}")

for forbidden in [
    'session_id="',
    "osmap_session=",
    "csrf_token=",
    "totp seed",
    "password=",
    "secret=",
]:
    pattern = re.compile(re.escape(forbidden), flags=re.IGNORECASE)
    for source_name, source in [
        ("V4 report", v4_report),
        ("V3 summary md", v3_summary_md),
        ("V3 summary json", json.dumps(v3_summary, sort_keys=True)),
    ]:
        if pattern.search(source):
            errors.append(f"{source_name} contains forbidden evidence text: {forbidden}")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
PY

echo "V4 closeout evidence checks passed"
