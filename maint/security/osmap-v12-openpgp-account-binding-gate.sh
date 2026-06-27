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

require_file docs/V12_OPENPGP_ACCOUNT_FINGERPRINT_BINDING.md
require_file maint/security/osmap-v12-openpgp-account-binding.py
require_file maint/security/osmap-v12-openpgp-account-binding-gate.sh
require_file maint/security/test-osmap-v12-openpgp-account-binding-gate.sh
require_file maint/security/v12-openpgp-account-bindings.example.json

python3 -m py_compile maint/security/osmap-v12-openpgp-account-binding.py
python3 -B maint/security/osmap-v12-openpgp-account-binding.py --self-test >/dev/null
python3 -B maint/security/osmap-v12-openpgp-account-binding.py --check maint/security/v12-openpgp-account-bindings.example.json >/dev/null

require_text docs/V12_OPENPGP_ACCOUNT_FINGERPRINT_BINDING.md 'email-address-only key matching'
require_text docs/V12_OPENPGP_ACCOUNT_FINGERPRINT_BINDING.md 'full primary OpenPGP fingerprint'
require_text docs/V12_OPENPGP_ACCOUNT_FINGERPRINT_BINDING.md 'short key ID'
require_text docs/V12_OPENPGP_ACCOUNT_FINGERPRINT_BINDING.md 'does not decrypt, verify signatures, sign, encrypt'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'Slice 3 adds account fingerprint binding validation only'
require_text docs/V12_OPENPGP_KEY_INVENTORY_AND_DIAGNOSTICS.md 'Slice 3 adds account binding validation'
require_text Makefile 'osmap-v12-openpgp-account-binding-gate.sh'
require_text maint/security/osmap-security-check.sh 'osmap-v12-openpgp-account-binding-gate.sh'

for token in '--list-secret-keys' '--export-secret-keys' '--decrypt' '--sign' '--clearsign' '--detach-sign' '--encrypt' '--passphrase'; do
  if grep -Fq -- "$token" maint/security/osmap-v12-openpgp-account-binding.py; then
    printf 'forbidden gpg argument in account binding helper: %s\n' "$token" >&2
    exit 1
  fi
done

printf 'V12 OpenPGP account binding gate passed\n'
