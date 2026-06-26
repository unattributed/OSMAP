#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v12-openpgp-diagnostics.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

python3 -B maint/security/osmap-v12-openpgp-diagnostics.py --self-test > "$tmp/self-test.out" 2>&1
if ! grep -Fq 'V12 OpenPGP diagnostics self-test passed' "$tmp/self-test.out"; then
  cat "$tmp/self-test.out" >&2
  printf 'diagnostics self-test did not report success\n' >&2
  exit 1
fi

python3 -B maint/security/osmap-v12-openpgp-diagnostics.py --output "$tmp/out" > "$tmp/run.out" 2>&1
if [ ! -f "$tmp/out/openpgp-diagnostics.json" ]; then
  cat "$tmp/run.out" >&2
  printf 'diagnostics JSON was not written\n' >&2
  exit 1
fi
if [ ! -f "$tmp/out/openpgp-diagnostics-summary.md" ]; then
  cat "$tmp/run.out" >&2
  printf 'diagnostics summary was not written\n' >&2
  exit 1
fi

python3 - "$tmp/out/openpgp-diagnostics.json" <<'INNERPY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
assert report['schema'] == 'osmap-v12-openpgp-diagnostics-v1'
inv = report['safety_invariants']
for key in [
    'private_key_material_collected',
    'secret_key_inventory_collected',
    'uid_values_collected',
    'passphrases_prompted_or_stored',
    'message_decryption_attempted',
    'message_signing_attempted',
    'message_encryption_attempted',
    'browser_request_handler_touched_keys',
]:
    assert inv[key] is False, key
assert report['public_key_inventory']['uid_values_omitted'] is True
INNERPY

if grep -R '@' "$tmp/out" >/dev/null 2>&1; then
  printf 'diagnostics output appears to contain an email-like user ID value\n' >&2
  grep -R '@' "$tmp/out" >&2 || true
  exit 1
fi

sh maint/security/osmap-v12-openpgp-diagnostics-gate.sh > "$tmp/gate.out" 2>&1
if ! grep -Fq 'V12 OpenPGP diagnostics gate passed' "$tmp/gate.out"; then
  cat "$tmp/gate.out" >&2
  printf 'diagnostics gate did not report success\n' >&2
  exit 1
fi

printf 'V12 OpenPGP diagnostics gate regression test passed\n'
