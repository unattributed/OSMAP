#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"

TMPDIR="$(mktemp -d -t osmap-v12-gpgme-readiness-test.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py --self-test >/dev/null

GOOD="$TMPDIR/good.json"
BAD_DIRECT="$TMPDIR/bad-direct-gpg.json"
BAD_CRYPTO="$TMPDIR/bad-crypto.json"
BAD_PROBE="$TMPDIR/bad-probe.json"
REPORT="$TMPDIR/report.json"

cat > "$GOOD" <<'JSON'
{
  "schema": "osmap-v12-openpgp-gpgme-readiness-policy-v1",
  "preferred_runtime_binding": "gpgme",
  "require_gpgme_for_crypto_operations": true,
  "allow_direct_gpg_runtime_for_crypto_operations": false,
  "allow_crypto_operations_in_slice5": false,
  "allow_secret_key_listing_in_slice5": false,
  "allow_passphrase_prompting_in_slice5": false,
  "allow_browser_handler_key_access_in_slice5": false,
  "allowed_metadata_probes": [
    "gpg --version",
    "gpgme-config --version",
    "pkg-config --modversion gpgme",
    "pkg-config --cflags --libs gpgme"
  ],
  "future_helper_requirement": "Later helper implementation must use GPGME behind validated account fingerprints."
}
JSON

python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py --config "$GOOD" --output "$REPORT"
python3 -m json.tool "$REPORT" >/dev/null

python3 - "$GOOD" "$BAD_DIRECT" <<'PY'
import json, sys
from pathlib import Path
src = Path(sys.argv[1]); dst = Path(sys.argv[2])
data = json.loads(src.read_text())
data["allow_direct_gpg_runtime_for_crypto_operations"] = True
dst.write_text(json.dumps(data), encoding="utf-8")
PY
if python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py --config "$BAD_DIRECT" --output "$TMPDIR/bad-direct-report.json" >/dev/null 2>&1; then
  echo "direct gpg runtime crypto policy unexpectedly accepted" >&2
  exit 1
fi

python3 - "$GOOD" "$BAD_CRYPTO" <<'PY'
import json, sys
from pathlib import Path
src = Path(sys.argv[1]); dst = Path(sys.argv[2])
data = json.loads(src.read_text())
data["allow_crypto_operations_in_slice5"] = True
dst.write_text(json.dumps(data), encoding="utf-8")
PY
if python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py --config "$BAD_CRYPTO" --output "$TMPDIR/bad-crypto-report.json" >/dev/null 2>&1; then
  echo "Slice 5 crypto policy unexpectedly accepted" >&2
  exit 1
fi

python3 - "$GOOD" "$BAD_PROBE" <<'PY'
import json, sys
from pathlib import Path
src = Path(sys.argv[1]); dst = Path(sys.argv[2])
data = json.loads(src.read_text())
data["allowed_metadata_probes"] = ["gpg --decrypt"]
dst.write_text(json.dumps(data), encoding="utf-8")
PY
if python3 maint/security/osmap-v12-openpgp-gpgme-readiness.py --config "$BAD_PROBE" --output "$TMPDIR/bad-probe-report.json" >/dev/null 2>&1; then
  echo "forbidden crypto probe unexpectedly accepted" >&2
  exit 1
fi

echo "V12 OpenPGP GPGME readiness gate regression test passed"
