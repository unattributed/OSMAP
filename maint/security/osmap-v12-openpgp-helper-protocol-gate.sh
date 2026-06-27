#!/bin/sh
set -eu

DOC="docs/V12_OPENPGP_HELPER_PROTOCOL.md"
VALIDATOR="maint/security/osmap-v12-openpgp-helper-protocol.py"
EXAMPLE="maint/security/v12-openpgp-helper-protocol.example.json"
REPORT="${TMPDIR:-/tmp}/osmap-v12-openpgp-helper-protocol-report.json"

require_file() {
  if [ ! -f "$1" ]; then
    echo "missing required file: $1" >&2
    exit 1
  fi
}

require_file "$DOC"
require_file "$VALIDATOR"
require_file "$EXAMPLE"
require_file "maint/security/test-osmap-v12-openpgp-helper-protocol-gate.sh"

python3 -m py_compile "$VALIDATOR"
python3 "$VALIDATOR" --self-test
python3 "$VALIDATOR" --config "$EXAMPLE" --output "$REPORT"
python3 -m json.tool "$REPORT" >/dev/null

python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not report.get("valid"):
    raise SystemExit("helper protocol report is not valid")
expected_false = [
    "message_decryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "message_encryption_attempted",
    "gpgme_runtime_invoked",
    "secret_key_access_attempted",
    "passphrases_prompted_or_stored",
    "browser_request_handler_touched_keys",
]
for key in expected_false:
    if report["safety_invariants"].get(key) is not False:
        raise SystemExit(f"safety invariant must be false: {key}")
for key in ("account_binding_required", "unknown_operation_fails_closed"):
    if report["safety_invariants"].get(key) is not True:
        raise SystemExit(f"safety invariant must be true: {key}")
if set(report.get("allowed_operations", [])) != {"capability_status", "policy_check", "diagnostic_ping"}:
    raise SystemExit("unexpected allowed operation set")
PY

# The validator is a schema checker only. It must not invoke OpenPGP tooling or
# cryptographic helpers. Safety invariant names such as gpgme_runtime_invoked
# are allowed when they are asserted false; actual process invocation and
# command-line operation tokens remain forbidden.
python3 - "$VALIDATOR" <<'PY'
import ast
import re
import sys
from pathlib import Path

validator = Path(sys.argv[1])
source = validator.read_text(encoding="utf-8")
tree = ast.parse(source, filename=str(validator))

for node in ast.walk(tree):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        names = [alias.name.split(".")[0] for alias in node.names]
        if any(name in {"subprocess", "pty"} for name in names):
            raise SystemExit("helper protocol validator must not import process execution modules")
    if isinstance(node, ast.Call):
        func = ast.unparse(node.func)
        if func in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
        }:
            raise SystemExit("helper protocol validator must not invoke process execution APIs")

for token in (
    "Command::new",
    "--decrypt",
    "--encrypt",
    "--sign",
    "--clearsign",
    "--detach-sign",
    "--verify",
    "--list-secret",
    "--export-secret",
):
    if token in source:
        raise SystemExit(f"helper protocol validator contains forbidden crypto command token: {token}")

for pattern in (
    r'["\']gpg["\']',
    r'["\']gpgme["\']',
    r'["\']gpgme-config["\']',
):
    if re.search(pattern, source):
        raise SystemExit("helper protocol validator must not name crypto tooling as an executable")

PY

for marker in \
  'OSMAP:V12-SLICE4-HELPER-PROTOCOL:START' \
  'OSMAP:V12-SLICE4-HELPER-PROTOCOL:END'
do
  if ! grep -q "$marker" docs/KNOWN_LIMITATIONS.md docs/README.md docs/SECURITY_MODEL.md docs/V12_OPENPGP_REQUIREMENTS_AND_CLAIMS.md; then
    echo "missing Slice 4 marker: $marker" >&2
    exit 1
  fi
done

if ! grep -q 'osmap-v12-openpgp-helper-protocol-gate.sh' Makefile; then
  echo "Makefile v12-check does not include helper protocol gate" >&2
  exit 1
fi
if ! grep -q 'test-osmap-v12-openpgp-helper-protocol-gate.sh' Makefile; then
  echo "Makefile v12-check does not include helper protocol regression test" >&2
  exit 1
fi
if ! grep -q 'osmap-v12-openpgp-helper-protocol-gate.sh' maint/security/osmap-security-check.sh; then
  echo "security-check does not include helper protocol gate" >&2
  exit 1
fi
if ! grep -q 'test-osmap-v12-openpgp-helper-protocol-gate.sh' maint/security/osmap-security-check.sh; then
  echo "security-check does not include helper protocol regression test" >&2
  exit 1
fi

echo "V12 OpenPGP helper protocol gate passed"
