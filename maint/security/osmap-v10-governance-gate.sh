#!/usr/bin/env sh
set -eu

fail() {
  printf '%s\n' "V10 governance gate failed: $*" >&2
  exit 1
}

require_file() {
  [ -s "$1" ] || fail "missing required file: $1"
}

require_text() {
  file="$1"
  text="$2"
  grep -Fq "$text" "$file" || fail "missing required text in $file: $text"
}

require_file docs/V10_INTAKE_AUDIT.md
require_file docs/V10_GOVERNANCE_STATUS.md
require_file docs/V10_CLAIMS_AND_LIMITATIONS.md
require_file docs/V10_ACCEPTANCE_GATE.md
require_file maint/security/v10-intake-inventory.json
require_file maint/security/v10-claims-boundary.json
require_file Makefile
require_file .github/workflows/security-check.yml

require_text Makefile "v10-check:"
require_text Makefile "acceptance-check:"
require_text Makefile "osmap-v10-governance-gate.sh"
require_text .github/workflows/security-check.yml "security-check / v10 governance"
require_text .github/workflows/security-check.yml "make v10-check"
require_text docs/README.md "V10_ACCEPTANCE_GATE.md"
require_text docs/README.md "V10_CLAIMS_AND_LIMITATIONS.md"
require_text docs/README.md "V10_GOVERNANCE_STATUS.md"
require_text docs/README.md "V10_INTAKE_AUDIT.md"
require_text docs/V10_ACCEPTANCE_GATE.md "make v10-check"
require_text docs/V10_ACCEPTANCE_GATE.md "make acceptance-check"
require_text docs/V10_ACCEPTANCE_GATE.md "does not claim release readiness"
require_text docs/V10_CLAIMS_AND_LIMITATIONS.md "general hostile-email safety"
require_text docs/V10_CLAIMS_AND_LIMITATIONS.md "broad public release readiness"

python3 - <<'EOPY'
from pathlib import Path
import json

def fail(message: str) -> None:
    raise SystemExit(f"V10 governance gate failed: {message}")

claims = json.loads(Path('maint/security/v10-claims-boundary.json').read_text(encoding='utf-8'))
if claims.get('schema_version', 0) < 3:
    fail('v10-claims-boundary schema_version must be at least 3')
if claims.get('slice') != 'V10 Slice 2':
    fail('v10-claims-boundary slice must be V10 Slice 2')
gates = claims.get('gate_status', {})
for key in ('acceptance_check_target_present', 'v10_check_target_present'):
    if gates.get(key) is not True:
        fail(f'gate_status.{key} must be true')
ci = claims.get('ci_visibility', {})
if ci.get('security_check_workflow_v10_job_present') is not True:
    fail('ci visibility for v10 governance job must be true')
counts = claims.get('carried_forward_slice0_signals', {})
expected = {
    'document_count': 155,
    'placeholder_file_count': 22,
    'rust_assumption_count': 712,
    'scan_match_count': 1494,
}
for key, value in expected.items():
    if counts.get(key) != value:
        fail(f'carried_forward_slice0_signals.{key} expected {value}, got {counts.get(key)!r}')
non_claims = ' '.join(claims.get('explicit_non_claims', []))
for phrase in ('general hostile-email safety', 'broad public release readiness', 'production deployment change'):
    if phrase not in non_claims:
        fail(f'explicit non-claim missing: {phrase}')
EOPY

printf '%s\n' 'V10 governance gate passed'
