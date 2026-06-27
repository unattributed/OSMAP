#!/bin/sh
set -eu

VALIDATOR="maint/security/osmap-v12-openpgp-helper-protocol.py"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/osmap-v12-helper-protocol-test.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM

GOOD="$TMP_ROOT/good.json"
BAD_CRYPTO="$TMP_ROOT/bad-crypto.json"
BAD_BINDING="$TMP_ROOT/bad-binding.json"
BAD_SECRET="$TMP_ROOT/bad-secret.json"

cat > "$GOOD" <<'JSON'
{
  "schema": "osmap-v12-openpgp-helper-protocol-v1",
  "helper_name": "osmap-openpgp-helper",
  "purpose": "regression good",
  "allowed_operations": ["capability_status", "policy_check", "diagnostic_ping"],
  "request_boundary": {
    "requires_request_id": true,
    "requires_account": true,
    "requires_validated_account_binding": true,
    "requires_full_fingerprint_for_key_scoped_operations": true,
    "rejects_short_key_ids": true,
    "rejects_email_only_key_matching": true,
    "rejects_uid_text_authorization": true,
    "unknown_operations_fail_closed": true,
    "message_material_transport": "opaque-reference-or-digest-only"
  },
  "response_boundary": {
    "bounded_status_values": ["ok", "rejected", "unavailable"],
    "redacted_error_required": true,
    "browser_trusted_html_allowed": false,
    "message_body_return_allowed": false,
    "private_key_material_return_allowed": false,
    "passphrase_return_allowed": false
  },
  "logging_boundary": {
    "log_plaintext_message_body": false,
    "log_decrypted_message_body": false,
    "log_passphrase": false,
    "log_private_key_material": false,
    "log_uid_values": false,
    "log_full_raw_message": false,
    "log_full_request_payload": false
  },
  "safety_invariants": {
    "message_decryption_implemented": false,
    "message_signature_verification_implemented": false,
    "message_signing_implemented": false,
    "message_encryption_implemented": false,
    "pgp_mime_parsing_implemented": false,
    "gpgme_runtime_invoked": false,
    "secret_key_access_attempted": false,
    "passphrases_prompted_or_stored": false,
    "browser_request_handler_touched_keys": false,
    "account_binding_required": true,
    "unknown_operation_fails_closed": true
  }
}
JSON

python3 "$VALIDATOR" --config "$GOOD" --output "$TMP_ROOT/good-report.json"
python3 -m json.tool "$TMP_ROOT/good-report.json" >/dev/null

python3 - "$GOOD" "$BAD_CRYPTO" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["allowed_operations"].append("decrypt_message")
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
PY
if python3 "$VALIDATOR" --config "$BAD_CRYPTO" --output "$TMP_ROOT/bad-crypto-report.json" >/dev/null 2>&1; then
  echo "crypto operation unexpectedly accepted" >&2
  exit 1
fi
if ! grep -q 'cryptographic operation is not allowed' "$TMP_ROOT/bad-crypto-report.json"; then
  echo "bad crypto operation failure did not produce expected evidence" >&2
  exit 1
fi

python3 - "$GOOD" "$BAD_BINDING" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["request_boundary"]["requires_validated_account_binding"] = False
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
PY
if python3 "$VALIDATOR" --config "$BAD_BINDING" --output "$TMP_ROOT/bad-binding-report.json" >/dev/null 2>&1; then
  echo "missing account binding unexpectedly accepted" >&2
  exit 1
fi
if ! grep -q 'requires_validated_account_binding' "$TMP_ROOT/bad-binding-report.json"; then
  echo "missing account binding failure did not produce expected evidence" >&2
  exit 1
fi

python3 - "$GOOD" "$BAD_SECRET" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
data["safety_invariants"]["secret_key_access_attempted"] = True
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
PY
if python3 "$VALIDATOR" --config "$BAD_SECRET" --output "$TMP_ROOT/bad-secret-report.json" >/dev/null 2>&1; then
  echo "secret key access unexpectedly accepted" >&2
  exit 1
fi
if ! grep -q 'secret_key_access_attempted' "$TMP_ROOT/bad-secret-report.json"; then
  echo "secret key failure did not produce expected evidence" >&2
  exit 1
fi

echo "V12 OpenPGP helper protocol gate regression test passed"
