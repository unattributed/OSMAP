#!/usr/bin/env python3
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "maint" / "security" / "v12-openpgp-helper-client-integration.example.json"
MAKEFILE = ROOT / "Makefile"
SECURITY_CHECK = ROOT / "maint" / "security" / "osmap-security-check.sh"
RUST_CLIENT = ROOT / "src" / "openpgp_helper_client.rs"
LIB = ROOT / "src" / "lib.rs"
HELPER_INVOCATION = ROOT / "maint" / "security" / "openpgp-helper" / "osmap-openpgp-helper-protocol-only.py"
RUST_GATE = ROOT / "maint" / "security" / "osmap-v12-openpgp-rust-helper-client-gate.sh"
INTEGRATION_DOC = ROOT / "docs" / "V12_OPENPGP_HELPER_CLIENT_INTEGRATION_GATE.md"
HTTP_DIR = ROOT / "src" / "http"

FORBIDDEN_RUST_RUNTIME = [
    "Command::new",
    "std::process::Command",
    "tokio::process",
    "duct::",
    "sh -c",
    "/bin/sh",
    "gpg --",
    "gpgme_op_",
]

REQUIRED_FALSE = [
    "browser_handlers_touch_openpgp_helper",
    "browser_ui_integrated",
    "decrypted_content_rendering_enabled",
    "direct_gpg_runtime_crypto_allowed",
    "helper_process_spawned_by_slice",
    "message_decryption_attempted",
    "message_encryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "passphrases_prompted_or_stored",
    "pgp_mime_parsing_attempted",
    "private_key_access_attempted",
    "secret_key_listing_attempted",
]


def fail(msg):
    print(msg, file=sys.stderr)
    return 1


def read(path):
    return path.read_text(encoding="utf-8")


def http_openpgp_references():
    refs = []
    if not HTTP_DIR.exists():
        return refs
    for path in sorted(HTTP_DIR.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        if "openpgp" in text.lower() or "OpenPgp" in text:
            refs.append(str(path.relative_to(ROOT)))
    return refs


def validate():
    required_paths = [CFG, MAKEFILE, SECURITY_CHECK, RUST_CLIENT, LIB, HELPER_INVOCATION, RUST_GATE, INTEGRATION_DOC]
    missing = [str(path.relative_to(ROOT)) for path in required_paths if not path.exists()]
    errors = []
    warnings = []
    if missing:
        errors.append("missing required files: " + ", ".join(missing))
        return errors, warnings

    cfg = json.loads(read(CFG))
    invariants = cfg.get("safety_invariants", {})
    bad = [name for name in REQUIRED_FALSE if invariants.get(name) is not False]
    if bad:
        errors.append("bad safety invariants: " + ", ".join(bad))

    rust_source = read(RUST_CLIENT)
    forbidden = [token for token in FORBIDDEN_RUST_RUNTIME if token in rust_source]
    if forbidden:
        errors.append("forbidden helper runtime token in Rust client: " + ", ".join(forbidden))

    required_rust = [
        "OpenPgpHelperInvocationPlan",
        "OPENPGP_HELPER_PROTOCOL_ARG",
        "MAX_HELPER_REQUEST_BYTES",
        "MAX_HELPER_STDOUT_BYTES",
        "MAX_HELPER_STDERR_BYTES",
        "DEFAULT_HELPER_TIMEOUT",
        "classify_helper_result",
    ]
    missing_rust = [snippet for snippet in required_rust if snippet not in rust_source]
    if missing_rust:
        errors.append("missing Rust helper-client boundary snippets: " + ", ".join(missing_rust))

    lib_text = read(LIB)
    if not re.search(r"pub\s+mod\s+openpgp_helper_client\s*;", lib_text):
        errors.append("src/lib.rs does not expose openpgp_helper_client")
    if lib_text.startswith("pub mod openpgp_helper_client;"):
        errors.append("openpgp_helper_client appears before crate docs")

    make_text = read(MAKEFILE)
    security_text = read(SECURITY_CHECK)
    required_make = [
        "osmap-v12-openpgp-helper-invocation-gate.sh",
        "osmap-v12-openpgp-rust-helper-client-gate.sh",
        "osmap-v12-openpgp-helper-client-integration-gate.sh",
        "test-osmap-v12-openpgp-helper-client-integration-gate.sh",
    ]
    missing_make = [item for item in required_make if item not in make_text]
    if missing_make:
        errors.append("Makefile v12-check missing gates: " + ", ".join(missing_make))
    missing_security = [item for item in required_make if item not in security_text]
    if missing_security:
        errors.append("security-check missing gates: " + ", ".join(missing_security))

    refs = http_openpgp_references()
    if refs:
        errors.append("browser-facing http handlers reference OpenPGP helper code: " + ", ".join(refs))

    return errors, warnings


def report():
    errors, warnings = validate()
    return {
        "schema": "osmap-v12-openpgp-helper-client-integration-report-v1",
        "integration_status": "available" if not errors else "blocked",
        "purpose": "Prove V12 helper client integration discipline without enabling runtime cryptography.",
        "checked_paths": [
            "src/openpgp_helper_client.rs",
            "src/lib.rs",
            "maint/security/openpgp-helper/osmap-openpgp-helper-protocol-only.py",
            "maint/security/osmap-v12-openpgp-rust-helper-client-gate.sh",
            "maint/security/osmap-v12-openpgp-helper-client-integration-gate.sh",
            "Makefile",
            "maint/security/osmap-security-check.sh",
        ],
        "safety_invariants": json.loads(read(CFG))["safety_invariants"] if CFG.exists() else {},
        "valid": not errors,
        "warnings": warnings,
        "errors": errors,
    }


def main():
    if "--self-test" in sys.argv:
        errors, _warnings = validate()
        if errors:
            return fail("; ".join(errors))
        print("V12 OpenPGP helper client integration self-test passed")
        return 0
    data = report()
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
