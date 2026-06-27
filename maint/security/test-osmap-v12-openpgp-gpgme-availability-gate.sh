#!/bin/sh
set -eu

TOOL="maint/security/osmap-v12-openpgp-gpgme-availability.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 "$TOOL" --self-test

cat > "$TMPDIR/bad-direct-gpg.json" <<'JSON'
{
  "schema": "osmap-v12-openpgp-gpgme-availability-v1",
  "purpose": "bad config",
  "dependency_policy": {
    "preferred_runtime_binding": "gpgme",
    "require_pkg_config_metadata": true,
    "require_no_direct_gpg_crypto_fallback": true,
    "direct_gpg_runtime_crypto_allowed": true,
    "runtime_crypto_enabled": false,
    "metadata_probe_only": true,
    "compile_or_link_probe_crypto_allowed": false
  },
  "remediation_policy": {
    "install_is_operator_controlled": true,
    "debian_packages": ["pkg-config", "libgpgme-dev"],
    "openbsd_packages": ["pkgconf", "gpgme"]
  },
  "safety_invariants": {
    "preferred_runtime_binding_is_gpgme": true,
    "gpgme_metadata_probe_only": true,
    "gpg_version_metadata_only": true,
    "runtime_crypto_enabled": false,
    "direct_gpg_runtime_crypto_allowed": false,
    "fallback_to_direct_gpg_crypto_allowed": false,
    "message_decryption_attempted": false,
    "message_signature_verification_attempted": false,
    "message_signing_attempted": false,
    "message_encryption_attempted": false,
    "pgp_mime_parsing_attempted": false,
    "passphrases_prompted_or_stored": false,
    "secret_key_access_attempted": false,
    "secret_key_listing_attempted": false,
    "browser_request_handler_touched_keys": false
  }
}
JSON
if python3 "$TOOL" --config "$TMPDIR/bad-direct-gpg.json" --report "$TMPDIR/bad-direct-gpg-report.json" >/dev/null 2>&1; then
  echo "bad direct gpg crypto config unexpectedly passed" >&2
  exit 1
fi

cat > "$TMPDIR/bad-secret-listing.json" <<'JSON'
{
  "schema": "osmap-v12-openpgp-gpgme-availability-v1",
  "purpose": "bad config",
  "dependency_policy": {
    "preferred_runtime_binding": "gpgme",
    "require_pkg_config_metadata": true,
    "require_no_direct_gpg_crypto_fallback": true,
    "direct_gpg_runtime_crypto_allowed": false,
    "runtime_crypto_enabled": false,
    "metadata_probe_only": true,
    "compile_or_link_probe_crypto_allowed": false
  },
  "remediation_policy": {
    "install_is_operator_controlled": true,
    "debian_packages": ["pkg-config", "libgpgme-dev"],
    "openbsd_packages": ["pkgconf", "gpgme"]
  },
  "safety_invariants": {
    "preferred_runtime_binding_is_gpgme": true,
    "gpgme_metadata_probe_only": true,
    "gpg_version_metadata_only": true,
    "runtime_crypto_enabled": false,
    "direct_gpg_runtime_crypto_allowed": false,
    "fallback_to_direct_gpg_crypto_allowed": false,
    "message_decryption_attempted": false,
    "message_signature_verification_attempted": false,
    "message_signing_attempted": false,
    "message_encryption_attempted": false,
    "pgp_mime_parsing_attempted": false,
    "passphrases_prompted_or_stored": false,
    "secret_key_access_attempted": false,
    "secret_key_listing_attempted": true,
    "browser_request_handler_touched_keys": false
  }
}
JSON
if python3 "$TOOL" --config "$TMPDIR/bad-secret-listing.json" --report "$TMPDIR/bad-secret-listing-report.json" >/dev/null 2>&1; then
  echo "bad secret-key listing config unexpectedly passed" >&2
  exit 1
fi

echo "V12 OpenPGP GPGME availability gate regression test passed"
