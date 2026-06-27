#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

tmp_doc="docs/osmap-v12-claims-term-regression.md"
out="/tmp/osmap-v12-claims-gate.$$.out"
cleanup() {
  rm -f "$tmp_doc" "$out"
}
trap cleanup EXIT INT TERM

printf 'The phrase unsafe mode is allowed because it is not the deprecated product label.\n' > "$tmp_doc"
sh maint/security/osmap-v12-openpgp-claims-gate.sh >"$out" 2>&1
if ! grep -Fq 'V12 OpenPGP claims boundary gate passed' "$out"; then
  cat "$out" >&2
  printf 'claims gate did not report success\n' >&2
  exit 1
fi

printf 'This deliberately uses Safe Mode as a forbidden product label.\n' > "$tmp_doc"
if sh maint/security/osmap-v12-openpgp-claims-gate.sh >"$out" 2>&1; then
  cat "$out" >&2
  printf 'claims gate accepted forbidden legacy terminology\n' >&2
  exit 1
fi
if ! grep -Fq 'legacy protected-rendering terminology found' "$out"; then
  cat "$out" >&2
  printf 'claims gate did not report the expected terminology failure\n' >&2
  exit 1
fi
rm -f "$tmp_doc" "$out"

sh maint/security/osmap-v12-openpgp-claims-gate.sh >"$out" 2>&1
if ! grep -Fq 'V12 OpenPGP claims boundary gate passed' "$out"; then
  cat "$out" >&2
  printf 'claims gate did not pass after regression cleanup\n' >&2
  exit 1
fi

python3 - <<'INNERPY'
from pathlib import Path
text = Path('docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md').read_text()
for forbidden in [
    'OpenPGP decryption is implemented',
    'OpenPGP signature verification is implemented',
    'OpenPGP signing is implemented',
    'OpenPGP encryption is implemented',
]:
    assert forbidden not in text, forbidden
assert 'After this documentation slice' in text
assert 'must not claim implemented OpenPGP decryption' in text
INNERPY

printf 'V12 OpenPGP claims gate regression test passed\n'
