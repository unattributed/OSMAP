#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v12-openpgp-account-binding.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

python3 -B maint/security/osmap-v12-openpgp-account-binding.py --self-test > "$tmp/self-test.out" 2>&1
if ! grep -Fq 'V12 OpenPGP account binding self-test passed' "$tmp/self-test.out"; then
  cat "$tmp/self-test.out" >&2
  printf 'account binding self-test did not report success\n' >&2
  exit 1
fi

python3 -B maint/security/osmap-v12-openpgp-account-binding.py \
  --check maint/security/v12-openpgp-account-bindings.example.json \
  --output "$tmp/report" > "$tmp/example.out" 2>&1
if [ ! -f "$tmp/report/openpgp-account-binding-report.json" ]; then
  cat "$tmp/example.out" >&2
  printf 'account binding JSON report was not written\n' >&2
  exit 1
fi
if [ ! -f "$tmp/report/openpgp-account-binding-summary.md" ]; then
  cat "$tmp/example.out" >&2
  printf 'account binding summary was not written\n' >&2
  exit 1
fi

python3 - "$tmp/report/openpgp-account-binding-report.json" <<'INNERPY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert report['schema'] == 'osmap-v12-openpgp-account-binding-report-v1'
assert report['valid'] is True
inv = report['safety_invariants']
assert inv['email_only_key_matching_allowed'] is False
assert inv['short_key_ids_allowed'] is False
assert inv['uid_text_authorization_allowed'] is False
assert inv['ambiguous_key_match_fails_closed'] is True
for key in [
    'message_decryption_attempted',
    'message_signature_verification_attempted',
    'message_signing_attempted',
    'message_encryption_attempted',
    'passphrases_prompted_or_stored',
    'private_key_material_collected',
    'browser_request_handler_touched_keys',
]:
    assert inv[key] is False, key
INNERPY

cat > "$tmp/short-key.json" <<'JSON'
{
  "schema": "osmap-v12-openpgp-account-bindings-v1",
  "accounts": [
    {
      "account": "alice@example.invalid",
      "openpgp_enabled": true,
      "primary_fingerprint": "D039F691",
      "allowed_fingerprints": ["D039F691"],
      "policy": {
        "require_explicit_fingerprint": true,
        "reject_email_only_key_match": true,
        "reject_short_key_ids": true,
        "ambiguous_match_fails_closed": true
      }
    }
  ]
}
JSON
if python3 -B maint/security/osmap-v12-openpgp-account-binding.py --check "$tmp/short-key.json" > "$tmp/short-key.out" 2>&1; then
  cat "$tmp/short-key.out" >&2
  printf 'short key ID config unexpectedly passed\n' >&2
  exit 1
fi

cat > "$tmp/email-only.json" <<'JSON'
{
  "schema": "osmap-v12-openpgp-account-bindings-v1",
  "accounts": [
    {
      "account": "alice@example.invalid",
      "openpgp_enabled": true,
      "primary_fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
      "allowed_fingerprints": ["0123456789ABCDEF0123456789ABCDEF01234567"],
      "match_by_email": true,
      "policy": {
        "require_explicit_fingerprint": true,
        "reject_email_only_key_match": true,
        "reject_short_key_ids": true,
        "ambiguous_match_fails_closed": true
      }
    }
  ]
}
JSON
if python3 -B maint/security/osmap-v12-openpgp-account-binding.py --check "$tmp/email-only.json" > "$tmp/email-only.out" 2>&1; then
  cat "$tmp/email-only.out" >&2
  printf 'email-only matching config unexpectedly passed\n' >&2
  exit 1
fi

cat > "$tmp/inventory.json" <<'JSON'
{
  "schema": "osmap-v12-openpgp-diagnostics-v1",
  "public_key_inventory": {
    "keys": [
      {"primary_fingerprint": "FEDCBA9876543210FEDCBA9876543210FEDCBA98"}
    ]
  }
}
JSON
if python3 -B maint/security/osmap-v12-openpgp-account-binding.py \
  --check maint/security/v12-openpgp-account-bindings.example.json \
  --inventory "$tmp/inventory.json" > "$tmp/missing-inventory.out" 2>&1; then
  cat "$tmp/missing-inventory.out" >&2
  printf 'missing inventory fingerprint unexpectedly passed\n' >&2
  exit 1
fi

sh maint/security/osmap-v12-openpgp-account-binding-gate.sh > "$tmp/gate.out" 2>&1
if ! grep -Fq 'V12 OpenPGP account binding gate passed' "$tmp/gate.out"; then
  cat "$tmp/gate.out" >&2
  printf 'account binding gate did not report success\n' >&2
  exit 1
fi

printf 'V12 OpenPGP account binding gate regression test passed\n'
