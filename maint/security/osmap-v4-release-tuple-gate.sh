#!/bin/sh
set -eu

repo_root=${OSMAP_V4_RELEASE_TUPLE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

: "${OSMAP_V4_RELEASE_TUPLE_CLOSEOUT:=docs/V4_CLOSEOUT_EVIDENCE.md}"
: "${OSMAP_V4_RELEASE_TUPLE_HANDOFF:=docs/V4_RELEASE_OPERATOR_HANDOFF.md}"
: "${OSMAP_V4_RELEASE_TUPLE_LIVE_V4_REPORT:=maint/live/latest-host-v4-hostile-content-report.txt}"
: "${OSMAP_V4_RELEASE_TUPLE_V3_SUMMARY:=maint/live/osmap-v3-release-evidence-summary.json}"
: "${OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_REPORT:=maint/live/osmap-v4-hostile-assurance-report.json}"
: "${OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_ARCHIVE:=maint/live/osmap-v4-hostile-assurance-evidence.tar.gz}"
: "${OSMAP_V4_RELEASE_TUPLE_CLAIM_MATRIX:=docs/V4_SECURITY_CLAIM_MATRIX.md}"
: "${OSMAP_V4_RELEASE_TUPLE_CURRENT_ASSURANCE_REF:=}"

for path in \
	"$OSMAP_V4_RELEASE_TUPLE_CLOSEOUT" \
	"$OSMAP_V4_RELEASE_TUPLE_HANDOFF" \
	"$OSMAP_V4_RELEASE_TUPLE_LIVE_V4_REPORT" \
	"$OSMAP_V4_RELEASE_TUPLE_V3_SUMMARY" \
	"$OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_REPORT" \
	"$OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_ARCHIVE" \
	"$OSMAP_V4_RELEASE_TUPLE_CLAIM_MATRIX"
do
	if [ ! -s "$path" ]; then
		echo "error: missing V4 release tuple input: $path" >&2
		exit 1
	fi
done

python3 - \
	"$repo_root" \
	"$OSMAP_V4_RELEASE_TUPLE_CLOSEOUT" \
	"$OSMAP_V4_RELEASE_TUPLE_HANDOFF" \
	"$OSMAP_V4_RELEASE_TUPLE_LIVE_V4_REPORT" \
	"$OSMAP_V4_RELEASE_TUPLE_V3_SUMMARY" \
	"$OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_REPORT" \
	"$OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_ARCHIVE" \
	"$OSMAP_V4_RELEASE_TUPLE_CLAIM_MATRIX" \
	"$OSMAP_V4_RELEASE_TUPLE_CURRENT_ASSURANCE_REF" <<'PY'
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

repo_root = Path(sys.argv[1])
closeout_path = Path(sys.argv[2])
handoff_path = Path(sys.argv[3])
live_v4_report_path = Path(sys.argv[4])
v3_summary_path = Path(sys.argv[5])
v4_assurance_report_path = Path(sys.argv[6])
v4_assurance_archive_path = Path(sys.argv[7])
claim_matrix_path = Path(sys.argv[8])
current_assurance_ref = sys.argv[9]

errors = []


def read(path):
    return path.read_text(encoding="utf-8", errors="replace")


def require_match(pattern, text, label):
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        errors.append(f"missing {label}")
        return ""
    return match.group(1)


def prefix_equal(left, right):
    return bool(left and right and (left.startswith(right) or right.startswith(left)))


def git(*args):
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def parse_key_values(text):
    values = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


closeout = read(closeout_path)
handoff = read(handoff_path)
live_v4 = read(live_v4_report_path)
claim_matrix = read(claim_matrix_path)
v3_summary = json.loads(read(v3_summary_path))
v4_assurance = json.loads(read(v4_assurance_report_path))

closeout_assessed = require_match(
    r"\| Assessed code commit \| `([0-9a-f]{7,40})` \|",
    closeout,
    "closeout assessed code commit",
)
handoff_tag = require_match(
    r"\| GitHub release tag \| `([^`]+)` \|",
    handoff,
    "handoff release tag",
)
handoff_bundle = require_match(
    r"\| Evidence bundle commit \| `([0-9a-f]{7,40})` \|",
    handoff,
    "handoff evidence bundle commit",
)
handoff_assessed = require_match(
    r"\| Assessed V4 code commit \| `([0-9a-f]{7,40})` \|",
    handoff,
    "handoff assessed V4 code commit",
)

live_values = parse_key_values(live_v4)
live_commit = live_values.get("commit", "")
live_result = live_values.get("result", "")
live_host = live_values.get("host", "")

if handoff_tag != "v4.0.0":
    errors.append(f"unexpected V4 release tag {handoff_tag!r}")
if not prefix_equal(closeout_assessed, handoff_assessed):
    errors.append(
        f"closeout assessed commit {closeout_assessed!r} does not match handoff assessed commit {handoff_assessed!r}"
    )
if not prefix_equal(closeout_assessed, live_commit):
    errors.append(
        f"live V4 proof commit {live_commit!r} does not match closeout assessed commit {closeout_assessed!r}"
    )
if live_host != "mail.blackbagsecurity.com":
    errors.append(f"live V4 proof host expected mail.blackbagsecurity.com, found {live_host!r}")
if live_result != "v4_hostile_content_live_proof_passed":
    errors.append(f"live V4 proof result expected pass marker, found {live_result!r}")

v3_assessed = v3_summary.get("assessed_ref", "")
if not prefix_equal(v3_assessed, closeout_assessed):
    errors.append(
        f"V3 carry-forward assessed_ref {v3_assessed!r} does not match closeout assessed commit {closeout_assessed!r}"
    )
if v3_summary.get("host_target") != "mail.blackbagsecurity.com":
    errors.append("V3 carry-forward host_target is not mail.blackbagsecurity.com")
if v3_summary.get("security_profile") != "release":
    errors.append("V3 carry-forward summary is not release profile")
if v3_summary.get("skipped_checks") != []:
    errors.append("V3 carry-forward summary contains skipped checks")
for field in [
    "sanitized_evidence_archive_status",
]:
    if v3_summary.get(field) != "passed":
        errors.append(f"V3 summary {field} expected passed, found {v3_summary.get(field)!r}")
if "v4_hostile_assurance_status" in v3_summary and v3_summary.get("v4_hostile_assurance_status") != "passed":
    errors.append(
        f"V3 summary v4_hostile_assurance_status expected passed when present, found {v3_summary.get('v4_hostile_assurance_status')!r}"
    )

for label, value in {
    "cargo build": v3_summary.get("cargo", {}).get("build"),
    "cargo test": v3_summary.get("cargo", {}).get("test"),
    "cargo clippy": v3_summary.get("cargo", {}).get("clippy"),
    "cargo fmt_check": v3_summary.get("cargo", {}).get("fmt_check"),
    "supply_chain": v3_summary.get("supply_chain"),
}.items():
    if value != "passed":
        errors.append(f"V3 summary {label} expected passed, found {value!r}")

if v4_assurance.get("schema") != "osmap-v4-hostile-assurance-report-v1":
    errors.append("V4 hostile assurance report schema is unexpected")
if v4_assurance.get("status") != "passed":
    errors.append("V4 hostile assurance report status is not passed")
v4_assessed = v4_assurance.get("assessed_ref", "")
if not v4_assessed:
    errors.append("V4 hostile assurance report missing assessed_ref")
if current_assurance_ref and not prefix_equal(v4_assessed, current_assurance_ref):
    errors.append(
        f"V4 hostile assurance report assessed_ref {v4_assessed!r} does not match current assurance ref {current_assurance_ref!r}"
    )

metadata = v4_assurance.get("evidence_metadata")
if not isinstance(metadata, dict):
    errors.append("V4 hostile assurance report missing evidence_metadata")
else:
    if metadata.get("schema") != "osmap-evidence-metadata-v1":
        errors.append("V4 hostile assurance evidence_metadata schema is unexpected")
    if metadata.get("git", {}).get("commit") != v4_assessed:
        errors.append("V4 hostile assurance evidence_metadata git commit does not match report assessed_ref")
    for tool in [
        "rustc",
        "cargo",
        "cargo_fmt",
        "cargo_clippy",
        "cargo_audit",
        "cargo_deny",
        "make",
    ]:
        state = metadata.get("tools", {}).get(tool)
        if not isinstance(state, dict):
            errors.append(f"V4 hostile assurance evidence_metadata missing {tool}")
        elif state.get("status") not in {"available", "unavailable"}:
            errors.append(f"V4 hostile assurance evidence_metadata {tool} has invalid status")

if "maint/security/osmap-v4-release-tuple-gate.sh" not in claim_matrix:
    errors.append("V4 security claim matrix does not reference the release tuple gate")
if "frozen V4.0.0 release tuple" not in claim_matrix:
    errors.append("V4 security claim matrix does not document the frozen/current assurance tuple distinction")

code, tag_commit, _ = git("rev-parse", "-q", "--verify", f"refs/tags/{handoff_tag}^{{}}")
if code != 0:
    errors.append(f"local repository is missing release tag {handoff_tag}")
elif not prefix_equal(tag_commit, handoff_bundle):
    errors.append(f"release tag {handoff_tag} resolves to {tag_commit!r}, not evidence bundle {handoff_bundle!r}")

for label, ref in [
    ("closeout assessed commit", closeout_assessed),
    ("handoff bundle commit", handoff_bundle),
    ("V3 carry-forward assessed_ref", v3_assessed),
    ("V4 hostile assurance assessed_ref", v4_assessed),
]:
    code, _, _ = git("cat-file", "-e", f"{ref}^{{commit}}")
    if code != 0:
        errors.append(f"{label} is not a local git commit: {ref!r}")

try:
    with tarfile.open(v4_assurance_archive_path, "r:gz") as archive:
        report_names = [
            member.name
            for member in archive.getmembers()
            if member.isfile() and member.name.endswith("osmap-v4-hostile-assurance-report.json")
        ]
        if not report_names:
            errors.append("V4 hostile assurance archive lacks report JSON")
        else:
            report_member = archive.extractfile(report_names[0])
            archived_report = json.loads(report_member.read().decode("utf-8"))
            if archived_report != v4_assurance:
                errors.append("V4 hostile assurance archive report does not match report JSON on disk")
except Exception as exc:
    errors.append(f"could not inspect V4 hostile assurance archive: {exc}")

if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)

print("V4 release tuple gate passed")
print(f"release_tag={handoff_tag}")
print(f"evidence_bundle_commit={handoff_bundle}")
print(f"frozen_assessed_commit={closeout_assessed}")
print(f"current_assurance_ref={v4_assessed}")
PY
