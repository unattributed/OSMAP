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

require_no_legacy_label() {
  python3 - <<'INNERPY'
from pathlib import Path
import re
import sys

pattern = re.compile(r"(?<![A-Za-z0-9_])safe[\s_-]+mode(?![A-Za-z0-9_])", re.IGNORECASE)
excluded_names = {
    "osmap-v12-openpgp-claims-gate.sh",
    "test-osmap-v12-openpgp-claims-gate.sh",
    "v12-openpgp-claims-boundary.json",
}
text_suffixes = {
    ".md", ".txt", ".rs", ".sh", ".ksh", ".py", ".json", ".toml", ".yml", ".yaml",
}
matches = []
for base_name in ("docs", "src", "maint"):
    base = Path(base_name)
    if not base.exists():
        continue
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.name in excluded_names:
            continue
        if path.suffix and path.suffix not in text_suffixes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                matches.append(f"{path}:{lineno}:{line}")

if matches:
    for match in matches:
        print(match, file=sys.stderr)
    print("legacy protected-rendering terminology found", file=sys.stderr)
    sys.exit(1)
INNERPY
}

require_file docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md
require_file maint/security/v12-openpgp-claims-boundary.json

python3 -m json.tool maint/security/v12-openpgp-claims-boundary.json >/dev/null

require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'Protected by Default'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'PGP/MIME first'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'GPGME'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'osmap-openpgp-helper'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'explicit configured fingerprints'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'Fail closed when more than one key matches'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'decrypted content as untrusted message content'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'verified signatures as authenticity metadata'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'Do not store OpenPGP passphrases'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'Do not log decrypted plaintext'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'encrypt-to-self'
require_text docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md 'It must not claim implemented OpenPGP decryption'

require_text maint/security/v12-openpgp-claims-boundary.json 'explicit_fingerprint_binding_required'
require_text maint/security/v12-openpgp-claims-boundary.json 'ambiguous_key_match_fails_closed'
require_text maint/security/v12-openpgp-claims-boundary.json 'decrypted_content_uses_secure_rendering_path'
require_text maint/security/v12-openpgp-claims-boundary.json 'verified_signature_does_not_bypass_content_safety'
require_text maint/security/v12-openpgp-claims-boundary.json 'passphrases_not_stored_by_osmap'
require_text maint/security/v12-openpgp-claims-boundary.json 'sensitive_plaintext_not_logged'

require_text docs/KNOWN_LIMITATIONS.md 'V12 OpenPGP bounded implementation track'
require_text docs/SECURITY_MODEL.md 'V12 OpenPGP security boundary'
require_text docs/README.md 'V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md'
require_text Makefile 'v12-check:'

require_no_legacy_label

python3 - <<'INNERPY'
import json
from pathlib import Path
claims = json.loads(Path('maint/security/v12-openpgp-claims-boundary.json').read_text())
required = claims['required_design_invariants']
missing = [key for key, value in required.items() if value is not True]
if missing:
    raise SystemExit('required invariant not true: ' + ', '.join(missing))
if not claims.get('current_forbidden_claims'):
    raise SystemExit('current_forbidden_claims must not be empty')
if not claims.get('current_allowed_claims'):
    raise SystemExit('current_allowed_claims must not be empty')
INNERPY

printf 'V12 OpenPGP claims boundary gate passed\n'
