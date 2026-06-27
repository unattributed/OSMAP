#!/bin/sh
set -eu

CONFIG="maint/security/v12-openpgp-gpgme-availability.example.json"
TOOL="maint/security/osmap-v12-openpgp-gpgme-availability.py"
DOC="docs/V12_OPENPGP_GPGME_AVAILABILITY.md"
REPORT="${TMPDIR:-/tmp}/osmap-v12-openpgp-gpgme-availability-report.json"
REQUIRE_FLAG=""

if [ "${OSMAP_V12_REQUIRE_GPGME_AVAILABLE:-0}" = "1" ]; then
  REQUIRE_FLAG="--require-available"
fi

test -f "$CONFIG"
test -x "$TOOL"
test -f "$DOC"
python3 -m py_compile "$TOOL"
python3 "$TOOL" --self-test
python3 "$TOOL" --config "$CONFIG" --report "$REPORT" $REQUIRE_FLAG
python3 - "$REPORT" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
errors = []
if report.get("schema") != "osmap-v12-openpgp-gpgme-availability-report-v1":
    errors.append("unexpected report schema")
if report.get("valid") is not True:
    errors.append("availability report is not valid")
if report.get("availability_status") not in {"available", "blocked_missing_gpgme"}:
    errors.append("unexpected availability_status")
inv = report.get("safety_invariants", {})
for key in ["runtime_crypto_enabled", "direct_gpg_runtime_crypto_allowed", "fallback_to_direct_gpg_crypto_allowed", "message_decryption_attempted", "message_signature_verification_attempted", "message_signing_attempted", "message_encryption_attempted", "pgp_mime_parsing_attempted", "passphrases_prompted_or_stored", "secret_key_access_attempted", "secret_key_listing_attempted", "browser_request_handler_touched_keys"]:
    if inv.get(key) is not False:
        errors.append(f"{key} must be false")
for key in ["preferred_runtime_binding_is_gpgme", "gpgme_metadata_probe_only", "gpg_version_metadata_only"]:
    if inv.get(key) is not True:
        errors.append(f"{key} must be true")
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
PY

if [ "${OSMAP_V12_REQUIRE_GPGME_AVAILABLE:-0}" = "1" ]; then
  python3 - "$REPORT" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
env = report.get("environment", {})
if report.get("availability_status") != "available":
    print("GPGME availability is required but not proven", file=sys.stderr)
    raise SystemExit(1)
if env.get("pkg_config_gpgme_available") is not True:
    print("pkg-config gpgme metadata must be available", file=sys.stderr)
    raise SystemExit(1)
compile_probe = env.get("compile_or_link_probe", {})
if compile_probe.get("attempted") is True and compile_probe.get("available") is not True:
    print("GPGME compile or link probe must pass", file=sys.stderr)
    raise SystemExit(1)
PY
fi

grep -q 'OSMAP:V12-SLICE6-GPGME-AVAILABILITY:START' docs/KNOWN_LIMITATIONS.md
grep -q 'OSMAP:V12-SLICE6-GPGME-AVAILABILITY:START' docs/README.md
grep -q 'OSMAP:V12-SLICE6-GPGME-AVAILABILITY:START' docs/SECURITY_MODEL.md
grep -q 'OSMAP:V12-SLICE6-GPGME-AVAILABILITY:START' docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md
grep -q 'OSMAP:V12-SLICE6-GPGME-AVAILABILITY:START' docs/V12_OPENPGP_GPGME_READINESS.md
grep -q 'osmap-v12-openpgp-gpgme-availability-gate.sh' Makefile
grep -q 'osmap-v12-openpgp-gpgme-availability-gate.sh' maint/security/osmap-security-check.sh

echo "V12 OpenPGP GPGME availability gate passed"
