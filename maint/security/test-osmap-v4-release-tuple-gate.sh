#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
gate="$repo_root/maint/security/osmap-v4-release-tuple-gate.sh"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v4-release-tuple.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

sh -n "$gate"

sh "$gate" > "$tmp_dir/positive.out"
grep -Fq "V4 release tuple gate passed" "$tmp_dir/positive.out"
grep -Fq "release_tag=v4.0.0" "$tmp_dir/positive.out"

cp "$repo_root/maint/live/osmap-v4-hostile-assurance-report.json" "$tmp_dir/assurance-failed.json"
python3 - "$tmp_dir/assurance-failed.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
report["status"] = "failed"
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if OSMAP_V4_RELEASE_TUPLE_V4_ASSURANCE_REPORT="$tmp_dir/assurance-failed.json" \
	sh "$gate" > "$tmp_dir/assurance-failed.out" 2>&1; then
	echo "expected tuple gate to fail for a failed assurance report" >&2
	exit 1
fi
grep -Fq "V4 hostile assurance report status is not passed" "$tmp_dir/assurance-failed.out"

cp "$repo_root/maint/live/latest-host-v4-hostile-content-report.txt" "$tmp_dir/live-commit-mismatch.txt"
python3 - "$tmp_dir/live-commit-mismatch.txt" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = []
for line in path.read_text(encoding="utf-8").splitlines():
    if line.startswith("commit="):
        lines.append("commit=deadbee")
    else:
        lines.append(line)
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

if OSMAP_V4_RELEASE_TUPLE_LIVE_V4_REPORT="$tmp_dir/live-commit-mismatch.txt" \
	sh "$gate" > "$tmp_dir/live-commit-mismatch.out" 2>&1; then
	echo "expected tuple gate to fail for a live proof commit mismatch" >&2
	exit 1
fi
grep -Fq "live V4 proof commit" "$tmp_dir/live-commit-mismatch.out"

echo "V4 release tuple gate regression checks passed"
