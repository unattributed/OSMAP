#!/usr/bin/env sh
set -eu

fail() {
  printf '%s\n' "V11 runtime fail-closed gate failed: $*" >&2
  exit 1
}

[ -s docs/V11_RUNTIME_FAIL_CLOSED_CLOSURE.md ] || fail "missing V11 closure document"
[ -s maint/security/v10-fail-closed-remediation.json ] || fail "missing V10 remediation register"

python3 - <<'EOPY'
from pathlib import Path
import json

register = json.loads(Path("maint/security/v10-fail-closed-remediation.json").read_text(encoding="utf-8"))
summary = register.get("summary", {})
if summary.get("high_relevance_after") != 0:
    raise SystemExit("V11 runtime fail-closed gate failed: high_relevance_after must be 0")
if summary.get("classification_complete") is not True:
    raise SystemExit("V11 runtime fail-closed gate failed: classification_complete must be true")
if summary.get("product_behavior_changed") is not False:
    raise SystemExit("V11 runtime fail-closed gate failed: product_behavior_changed must be false")
if summary.get("production_state_changed") is not False:
    raise SystemExit("V11 runtime fail-closed gate failed: production_state_changed must be false")
if summary.get("live_host_state_changed") is not False:
    raise SystemExit("V11 runtime fail-closed gate failed: live_host_state_changed must be false")
EOPY

python3 -B maint/security/osmap-v10-fail-closed-remediation.py --check maint/security/v10-fail-closed-remediation.json

grep -Fq 'high-relevance assumptions after V11 remediation: `0`' docs/V11_RUNTIME_FAIL_CLOSED_CLOSURE.md || fail "V11 closure document must record zero refined high-relevance assumptions"
grep -Fq "mailbox-helper-config" docs/V11_RUNTIME_FAIL_CLOSED_CLOSURE.md || fail "V11 closure document must record helper config fail-closed behavior"
grep -Fq "mailbox_helper_grant_key_path_missing" docs/V11_RUNTIME_FAIL_CLOSED_CLOSURE.md || fail "V11 closure document must record attachment helper failure reason"

printf '%s\n' 'V11 runtime fail-closed gate passed'
