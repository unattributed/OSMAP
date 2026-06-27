#!/bin/sh
set -eu

CONFIG="maint/security/v12-openpgp-helper-invocation.example.json"
REPORT="${OSMAP_V12_HELPER_INVOCATION_REPORT:-/tmp/osmap-v12-openpgp-helper-invocation-report.json}"

python3 maint/security/osmap-v12-openpgp-helper-invocation.py --self-test
python3 maint/security/osmap-v12-openpgp-helper-invocation.py --config "$CONFIG" --report "$REPORT" >/dev/null
python3 -m json.tool "$REPORT" >/dev/null
python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not report.get("valid"):
    print("V12 OpenPGP helper invocation gate failed", file=sys.stderr)
    for error in report.get("errors", []):
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)
if report.get("invocation_scaffold_status") != "available":
    print("helper invocation scaffold is not available", file=sys.stderr)
    raise SystemExit(1)
for name, case in report.get("invocation_matrix", {}).items():
    stdout = case.get("stdout") or {}
    if stdout.get("runtime_crypto_enabled") is not False:
        print(f"{name} did not report runtime_crypto_enabled false", file=sys.stderr)
        raise SystemExit(1)
print("V12 OpenPGP helper invocation scaffold gate passed")
PY
