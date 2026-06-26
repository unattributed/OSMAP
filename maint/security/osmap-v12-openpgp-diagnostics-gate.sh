#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

require_file() {
  if [ ! -f "$1" ]; then
    printf 'missing required file: %s\n' "$1" >&2
    exit 1
  fi
}

require_text() {
  file="$1"
  text="$2"
  if ! grep -Fq "$text" "$file"; then
    printf 'missing required text in %s: %s\n' "$file" "$text" >&2
    exit 1
  fi
}

require_file maint/security/osmap-v12-openpgp-diagnostics.py
require_file maint/security/osmap-v12-openpgp-diagnostics-gate.sh
require_file maint/security/test-osmap-v12-openpgp-diagnostics-gate.sh
require_file docs/V12_OPENPGP_KEY_INVENTORY_AND_DIAGNOSTICS.md

python3 -m py_compile maint/security/osmap-v12-openpgp-diagnostics.py
python3 -B maint/security/osmap-v12-openpgp-diagnostics.py --self-test >/dev/null

require_text docs/V12_OPENPGP_KEY_INVENTORY_AND_DIAGNOSTICS.md 'diagnostics only'
require_text docs/V12_OPENPGP_KEY_INVENTORY_AND_DIAGNOSTICS.md 'must not list secret keys'
require_text docs/V12_OPENPGP_KEY_INVENTORY_AND_DIAGNOSTICS.md 'must not collect user ID values'
require_text docs/V12_OPENPGP_KEY_INVENTORY_AND_DIAGNOSTICS.md 'must not decrypt, sign, or encrypt mail'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'Slice 2 adds diagnostics only'
require_text Makefile 'osmap-v12-openpgp-diagnostics-gate.sh'
require_text maint/security/osmap-security-check.sh 'osmap-v12-openpgp-diagnostics-gate.sh'

for token in '--list-secret-keys' '--export-secret-keys' '--decrypt' '--sign' '--clearsign' '--detach-sign' '--passphrase'; do
  if grep -Fq -- "$token" maint/security/osmap-v12-openpgp-diagnostics.py; then
    printf 'forbidden gpg argument in diagnostics helper: %s\n' "$token" >&2
    exit 1
  fi
done

printf 'V12 OpenPGP diagnostics gate passed\n'
