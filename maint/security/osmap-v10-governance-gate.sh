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
require_file docs/V10_DOCUMENTATION_STATUS_CLOSURE.md
require_file docs/V10_RUST_ASSUMPTION_FAIL_CLOSED_AUDIT.md
require_file maint/security/v10-intake-inventory.json
require_file maint/security/v10-claims-boundary.json
require_file maint/security/v10-documentation-status-closure.json
require_file maint/security/v10-rust-assumption-audit.json
require_file maint/security/osmap-v10-rust-assumption-audit.py
require_file Makefile
require_file .github/workflows/security-check.yml

require_text Makefile "v10-check:"
require_text Makefile "acceptance-check:"
require_text Makefile "osmap-v10-governance-gate.sh"
require_text .github/workflows/security-check.yml "security-check / v10 governance"
require_text .github/workflows/security-check.yml "make v10-check"
require_text docs/README.md "V10_RUST_ASSUMPTION_FAIL_CLOSED_AUDIT.md"
require_text docs/README.md "V10_DOCUMENTATION_STATUS_CLOSURE.md"
require_text docs/README.md "V10_ACCEPTANCE_GATE.md"
require_text docs/README.md "V10_CLAIMS_AND_LIMITATIONS.md"
require_text docs/README.md "V10_GOVERNANCE_STATUS.md"
require_text docs/README.md "V10_INTAKE_AUDIT.md"
require_text docs/V10_ACCEPTANCE_GATE.md "make v10-check"
require_text docs/V10_ACCEPTANCE_GATE.md "make acceptance-check"
require_text docs/V10_ACCEPTANCE_GATE.md "does not claim release readiness"
require_text docs/V10_CLAIMS_AND_LIMITATIONS.md "general hostile-email safety"
require_text docs/V10_CLAIMS_AND_LIMITATIONS.md "broad public release readiness"
require_text docs/V10_CLAIMS_AND_LIMITATIONS.md "V10 Slice 4"
require_text docs/V10_DOCUMENTATION_STATUS_CLOSURE.md "Placeholder inventory classification"
require_text docs/V10_DOCUMENTATION_STATUS_CLOSURE.md "Stale-status and version-reference classification"
require_text docs/V10_DOCUMENTATION_STATUS_CLOSURE.md "This closure does not claim"
require_text docs/V10_RUST_ASSUMPTION_FAIL_CLOSED_AUDIT.md "Current normalized scanner count"
require_text docs/V10_RUST_ASSUMPTION_FAIL_CLOSED_AUDIT.md "This closure does not claim"

python3 - <<'EOPY'
from pathlib import Path
import json

def fail(message: str) -> None:
    raise SystemExit(f"V10 governance gate failed: {message}")

claims = json.loads(Path('maint/security/v10-claims-boundary.json').read_text(encoding='utf-8'))
closure = json.loads(Path('maint/security/v10-documentation-status-closure.json').read_text(encoding='utf-8'))
rust = json.loads(Path('maint/security/v10-rust-assumption-audit.json').read_text(encoding='utf-8'))

if claims.get('schema_version', 0) < 5:
    fail('v10-claims-boundary schema_version must be at least 5')
if claims.get('slice') != 'V10 Slice 4':
    fail('v10-claims-boundary slice must be V10 Slice 4')

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

status = claims.get('documentation_status_closure', {})
if status.get('placeholder_inventory_classified') is not True:
    fail('documentation_status_closure.placeholder_inventory_classified must be true')
if status.get('stale_status_language_classified') is not True:
    fail('documentation_status_closure.stale_status_language_classified must be true')
if status.get('closure_document_present') is not True:
    fail('documentation_status_closure.closure_document_present must be true')

summary = closure.get('closure_summary', {})
if closure.get('schema_version') != 1:
    fail('documentation closure schema_version must be 1')
if closure.get('slice') != 'V10 Slice 3':
    fail('documentation closure slice must be V10 Slice 3')
if summary.get('classification_complete') is not True:
    fail('documentation closure classification_complete must be true')

rust_status = claims.get('rust_assumption_fail_closed_audit', {})
rust_summary = rust.get('summary', {})
if rust.get('schema_version') != 1:
    fail('rust assumption audit schema_version must be 1')
if rust.get('slice') != 'V10 Slice 4':
    fail('rust assumption audit slice must be V10 Slice 4')
if rust_summary.get('classification_complete') is not True:
    fail('rust assumption audit classification_complete must be true')
if rust_summary.get('product_behavior_changed') is not False:
    fail('rust assumption audit product_behavior_changed must be false')
if rust_summary.get('production_state_changed') is not False:
    fail('rust assumption audit production_state_changed must be false')
if rust_summary.get('live_host_state_changed') is not False:
    fail('rust assumption audit live_host_state_changed must be false')
if rust_summary.get('slice0_carried_forward_rust_assumption_count') != 712:
    fail('rust assumption audit must carry forward Slice 0 count 712')
if rust_status.get('classification_complete') is not True:
    fail('rust_assumption_fail_closed_audit.classification_complete must be true')
if rust_status.get('audit_register_present') is not True:
    fail('rust_assumption_fail_closed_audit.audit_register_present must be true')
if rust_status.get('current_scanner_count') != rust_summary.get('total_count'):
    fail('rust_assumption_fail_closed_audit current count must match register')
if rust_status.get('inventory_sha256') != rust_summary.get('inventory_sha256'):
    fail('rust_assumption_fail_closed_audit inventory hash must match register')

non_claims = ' '.join(claims.get('explicit_non_claims', []))
for phrase in (
    'general hostile-email safety',
    'broad public release readiness',
    'production deployment change',
    'all Rust assumptions are safe',
    'panic-free production paths have been proven',
):
    if phrase not in non_claims:
        fail(f'explicit non-claim missing: {phrase}')
EOPY

PYTHONDONTWRITEBYTECODE=1 python3 -B maint/security/osmap-v10-rust-assumption-audit.py --check maint/security/v10-rust-assumption-audit.json

printf '%s\n' 'V10 governance gate passed'
