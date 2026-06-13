#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
gate="$repo_root/maint/security/osmap-v4-security-claim-matrix-gate.sh"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v4-claim-matrix.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

sh -n "$gate"

sh "$gate" > "$tmp_dir/positive.out"
grep -Fq "V4 security claim matrix gate passed" "$tmp_dir/positive.out"

cp "$repo_root/docs/V4_SECURITY_CLAIM_MATRIX.md" "$tmp_dir/blank-nongoal.md"
python3 - "$tmp_dir/blank-nongoal.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = "| Browser isolation headers preserve the mail/browser boundary |"
lines = []
for line in text.splitlines():
    if line.startswith(needle):
        cells = line.strip().strip("|").split("|")
        cells[-1] = " "
        line = "|" + "|".join(cells) + "|"
    lines.append(line)
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

if OSMAP_V4_CLAIM_MATRIX_DOC="$tmp_dir/blank-nongoal.md" \
	sh "$gate" > "$tmp_dir/blank-nongoal.out" 2>&1; then
	echo "expected claim matrix gate to fail for a blank non-goal" >&2
	exit 1
fi
grep -Fq "empty 'Non-goal' cell" "$tmp_dir/blank-nongoal.out"

cp "$repo_root/maint/live/osmap-v4-hostile-assurance-report.json" "$tmp_dir/report-with-fetch.json"
python3 - "$tmp_dir/report-with-fetch.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
report["network_assertions"]["remote_fetches"] = 1
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if OSMAP_V4_CLAIM_MATRIX_REPORT="$tmp_dir/report-with-fetch.json" \
	sh "$gate" > "$tmp_dir/report-with-fetch.out" 2>&1; then
	echo "expected claim matrix gate to fail for nonzero remote fetch evidence" >&2
	exit 1
fi
grep -Fq "remote_fetches expected 0" "$tmp_dir/report-with-fetch.out"

echo "V4 security claim matrix gate regression checks passed"
