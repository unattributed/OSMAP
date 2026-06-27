#!/bin/sh
set -eu

python3 maint/security/osmap-v12-openpgp-helper-invocation.py --self-test

TMPDIR="$(mktemp -d /tmp/osmap-v12-helper-invocation-test.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

GOOD="maint/security/v12-openpgp-helper-invocation.example.json"
BAD_CONFIG="$TMPDIR/bad-config.json"
BAD_HELPER="$TMPDIR/bad-helper.py"
REPORT="$TMPDIR/report.json"

python3 - "$GOOD" "$BAD_CONFIG" <<'PY'
import json
import sys
from pathlib import Path
src = Path(sys.argv[1])
dst = Path(sys.argv[2])
data = json.loads(src.read_text(encoding="utf-8"))
data["safety_invariants"]["runtime_crypto_enabled"] = True
dst.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 maint/security/osmap-v12-openpgp-helper-invocation.py --config "$BAD_CONFIG" --report "$REPORT" >/dev/null 2>&1; then
  echo "bad runtime_crypto_enabled invariant unexpectedly passed" >&2
  exit 1
fi

cat > "$BAD_HELPER" <<'PY'
#!/usr/bin/env python3
MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 8192
ALLOWED_OPERATIONS = set()
import os
os.system("date")
PY
chmod +x "$BAD_HELPER"

if python3 maint/security/osmap-v12-openpgp-helper-invocation.py --config "$GOOD" --helper "$BAD_HELPER" --report "$REPORT" >/dev/null 2>&1; then
  echo "bad helper source unexpectedly passed" >&2
  exit 1
fi

OSMAP_V12_HELPER_INVOCATION_REPORT="$REPORT" sh maint/security/osmap-v12-openpgp-helper-invocation-gate.sh >/dev/null

echo "V12 OpenPGP helper invocation scaffold gate regression test passed"
