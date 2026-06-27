#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"

REPORT="$(mktemp -t osmap-v12-gpgme-readiness-report.XXXXXX.json)"
trap 'rm -f "$REPORT"' EXIT INT TERM

python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py --self-test
python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py \
  --config maint/security/v12-openpgp-gpgme-readiness.example.json \
  --output "$REPORT"
python3 -m json.tool "$REPORT" >/dev/null
python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not report.get("valid"):
    raise SystemExit("GPGME readiness report is invalid")
status = report.get("readiness_status")
if status not in {"ready_for_gpgme_design_only", "blocked_missing_gpgme"}:
    raise SystemExit(f"unexpected readiness status: {status}")
expected_false = [
    "direct_gpg_runtime_crypto_allowed",
    "fallback_to_direct_gpg_crypto_allowed",
    "runtime_crypto_enabled",
    "message_decryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "message_encryption_attempted",
    "pgp_mime_parsing_attempted",
    "secret_key_listing_attempted",
    "secret_key_access_attempted",
    "passphrases_prompted_or_stored",
    "browser_request_handler_touched_keys",
]
for key in expected_false:
    if report["safety_invariants"].get(key) is not False:
        raise SystemExit(f"unexpected true invariant: {key}")
for key in ["preferred_runtime_binding_is_gpgme", "gpg_version_metadata_only", "gpgme_metadata_probe_only"]:
    if report["safety_invariants"].get(key) is not True:
        raise SystemExit(f"missing true invariant: {key}")
PY

echo "V12 OpenPGP GPGME readiness gate passed"
