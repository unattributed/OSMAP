#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "maint" / "security" / "v12-openpgp-closeout-readiness.example.json"
MAKEFILE = ROOT / "Makefile"
SECURITY_CHECK = ROOT / "maint" / "security" / "osmap-security-check.sh"
DOC = ROOT / "docs" / "V12_OPENPGP_CLOSEOUT_READINESS_AUDIT.md"
HTTP_DIR = ROOT / "src" / "http"
RUST_CLIENT = ROOT / "src" / "openpgp_helper_client.rs"
HELPER_PROTOCOL = ROOT / "maint" / "security" / "openpgp-helper" / "osmap-openpgp-helper-protocol-only.py"

REQUIRED_FALSE = [
    "browser_ui_integrated",
    "browser_handlers_touch_keys",
    "decrypted_body_logged",
    "decrypted_content_rendering_enabled",
    "direct_gpg_runtime_crypto_allowed",
    "helper_process_spawning_enabled",
    "key_discovery_enabled",
    "keyserver_lookup_enabled",
    "message_decryption_enabled",
    "message_encryption_enabled",
    "message_signature_verification_enabled",
    "message_signing_enabled",
    "passphrase_handling_enabled",
    "pgp_mime_construction_enabled",
    "pgp_mime_parsing_enabled",
    "private_key_access_enabled",
    "raw_decrypted_body_persisted",
    "wkd_lookup_enabled",
]

REQUIRED_DOC_PHRASES = [
    "This slice does not add OpenPGP runtime functionality",
    "All V12 OpenPGP gates are present in `make v12-check`",
    "All V12 OpenPGP gates are present in `make security-check`",
    "Browser handlers do not touch OpenPGP key material",
    "Helper process spawning is not enabled by V12",
    "PGP/MIME parsing is not enabled by V12",
    "Decrypt, verify, sign, and encrypt paths are not enabled by V12",
    "stale V3 live evidence",
]


def fail(message):
    print(message, file=sys.stderr)
    return 1


def read(path):
    return path.read_text(encoding="utf-8")


def http_openpgp_references():
    refs = []
    if not HTTP_DIR.exists():
        return refs
    for path in sorted(HTTP_DIR.rglob("*.rs")):
        text = read(path)
        if "openpgp" in text.lower() or "OpenPgp" in text:
            refs.append(str(path.relative_to(ROOT)))
    return refs


def validate():
    errors = []
    warnings = []
    for path in [CFG, MAKEFILE, SECURITY_CHECK, DOC, RUST_CLIENT, HELPER_PROTOCOL]:
        if not path.exists():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")
    if errors:
        return errors, warnings

    cfg = json.loads(read(CFG))
    if cfg.get("schema") != "osmap-v12-openpgp-closeout-readiness-v1":
        errors.append("unexpected schema")

    gates = cfg.get("expected_gates", [])
    if not isinstance(gates, list) or len(gates) < 20:
        errors.append("expected_gates must include the full V12 gate inventory")
        gates = []

    make_text = read(MAKEFILE)
    security_text = read(SECURITY_CHECK)
    missing_make = [gate for gate in gates if gate not in make_text]
    missing_security = [gate for gate in gates if gate not in security_text]
    if missing_make:
        errors.append("Makefile v12-check missing gates: " + ", ".join(missing_make))
    if missing_security:
        errors.append("security-check missing gates: " + ", ".join(missing_security))

    docs = cfg.get("required_documents", [])
    missing_docs = [doc for doc in docs if not (ROOT / doc).exists()]
    if missing_docs:
        errors.append("missing V12 documents: " + ", ".join(missing_docs))

    invariants = cfg.get("safety_invariants", {})
    bad = [name for name in REQUIRED_FALSE if invariants.get(name) is not False]
    if bad:
        errors.append("bad safety invariants: " + ", ".join(bad))

    if cfg.get("known_carried_forward_items", {}).get("make_release_check_stale_v3_live_evidence") is not True:
        errors.append("known release-check stale V3 live evidence carry-forward item is not acknowledged")

    doc_text = read(DOC)
    missing_doc_phrases = [phrase for phrase in REQUIRED_DOC_PHRASES if phrase not in doc_text]
    if missing_doc_phrases:
        errors.append("closeout readiness doc missing phrases: " + ", ".join(missing_doc_phrases))

    refs = http_openpgp_references()
    if refs:
        errors.append("browser-facing HTTP handlers reference OpenPGP: " + ", ".join(refs))

    rust_text = read(RUST_CLIENT)
    forbidden_rust = [
        "Command::new",
        "std::process::Command",
        ".spawn(",
        ".output(",
        "/bin/sh",
        "sh -c",
        "gpgme_op_",
    ]
    found_rust = [token for token in forbidden_rust if token in rust_text]
    if found_rust:
        errors.append("Rust helper client enables runtime process or crypto behavior: " + ", ".join(found_rust))

    helper_text = read(HELPER_PROTOCOL)
    required_helper_tokens = ["capability_status", "diagnostic_ping", "policy_check"]
    missing_helper = [token for token in required_helper_tokens if token not in helper_text]
    if missing_helper:
        errors.append("protocol-only helper missing expected non-crypto operations: " + ", ".join(missing_helper))

    return errors, warnings


def report():
    errors, warnings = validate()
    cfg = json.loads(read(CFG)) if CFG.exists() else {}
    gates = cfg.get("expected_gates", [])
    return {
        "schema": "osmap-v12-openpgp-closeout-readiness-report-v1",
        "closeout_readiness_status": "ready_for_review" if not errors else "blocked",
        "purpose": "Audit V12 OpenPGP non-cryptographic foundation readiness before future cryptographic implementation.",
        "gate_count": len(gates),
        "document_count": len(cfg.get("required_documents", [])),
        "known_carried_forward_items": cfg.get("known_carried_forward_items", {}),
        "safety_invariants": cfg.get("safety_invariants", {}),
        "valid": not errors,
        "warnings": warnings,
        "errors": errors,
    }


def main():
    if "--self-test" in sys.argv:
        errors, _warnings = validate()
        if errors:
            return fail("; ".join(errors))
        print("V12 OpenPGP closeout readiness audit self-test passed")
        return 0
    data = report()
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
