#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "maint" / "security" / "v12-openpgp-inbound-security-state.example.json"
MAKEFILE = ROOT / "Makefile"
SECURITY_CHECK = ROOT / "maint" / "security" / "osmap-security-check.sh"
DOC = ROOT / "docs" / "V12_OPENPGP_INBOUND_SECURITY_STATE_MODEL.md"
HTTP_DIR = ROOT / "src" / "http"

REQUIRED_FALSE = [
    "browser_ui_integrated",
    "browser_handlers_touch_openpgp_state",
    "browser_handlers_touch_keys",
    "decrypted_body_logged",
    "decrypted_content_rendering_enabled",
    "direct_gpg_runtime_crypto_allowed",
    "helper_process_spawned_by_slice",
    "key_discovery_enabled",
    "keyserver_lookup_enabled",
    "message_decryption_attempted",
    "message_encryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "passphrases_prompted_or_stored",
    "pgp_mime_construction_enabled",
    "pgp_mime_parsing_attempted",
    "private_key_access_attempted",
    "raw_decrypted_body_persisted",
    "signature_verification_trusted_for_content_safety",
    "wkd_lookup_enabled",
]

REQUIRED_CASE_NAMES = {
    "encrypted_not_decrypted",
    "signed_not_trusted",
    "verified_not_safe",
    "decrypted_not_renderable",
    "renderable_requires_secure_path",
    "failed_or_ambiguous_fails_closed",
    "unsigned_unencrypted_normal_path",
}


def fail(message):
    print(message, file=sys.stderr)
    return 1


def read(path):
    return path.read_text(encoding="utf-8")


def decide(case):
    state = case.get("input_state", {})
    if state.get("failed") is True or state.get("ambiguous") is True:
        return "fail_closed", "ambiguous_or_failed_inbound_security_state"
    if state.get("openpgp_label_detected") is not True:
        if state.get("rendered_through_secure_path") is True:
            return "normal_secure_rendering_path", "no_openpgp_claims"
        return "hold_closed", "normal_message_requires_existing_secure_rendering_path"
    if state.get("encrypted") is True and state.get("decrypted") is not True:
        return "hold_closed", "encrypted_content_not_decrypted"
    if state.get("decrypted") is True and state.get("rendered_through_secure_path") is not True:
        return "hold_closed", "decrypted_content_requires_secure_rendering"
    if state.get("signed") is True and state.get("verified") is True:
        if state.get("rendered_through_secure_path") is True and state.get("decrypted") is True:
            return "renderable_after_secure_path", "content_renderable_only_after_secure_path"
        return "metadata_only", "verified_signature_does_not_make_content_safe"
    if state.get("signed") is True:
        return "metadata_only", "signature_present_but_not_trusted"
    if state.get("rendered_through_secure_path") is True:
        return "renderable_after_secure_path", "content_renderable_only_after_secure_path"
    return "hold_closed", "openpgp_content_requires_secure_rendering"


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
    errors = []
    warnings = []
    for path in [CFG, MAKEFILE, SECURITY_CHECK, DOC]:
        if not path.exists():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")
    if errors:
        return errors, warnings, []

    cfg = json.loads(read(CFG))
    if cfg.get("schema") != "osmap-v12-openpgp-inbound-security-state-v1":
        errors.append("unexpected schema")
    cases = cfg.get("state_cases")
    if not isinstance(cases, list) or not cases:
        errors.append("state_cases must be a nonempty list")
        cases = []

    names = {case.get("name") for case in cases if isinstance(case, dict)}
    missing = sorted(REQUIRED_CASE_NAMES - names)
    if missing:
        errors.append("missing required state cases: " + ", ".join(missing))

    decisions = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("state case entry is not an object")
            continue
        name = case.get("name", "<unnamed>")
        decision, outcome = decide(case)
        decisions.append({"name": name, "decision": decision, "outcome": outcome})
        if decision != case.get("expected_decision"):
            errors.append(f"{name}: expected_decision mismatch: expected {case.get('expected_decision')} got {decision}")
        if outcome != case.get("expected_outcome"):
            errors.append(f"{name}: expected_outcome mismatch: expected {case.get('expected_outcome')} got {outcome}")

    invariants = cfg.get("safety_invariants", {})
    bad_invariants = [name for name in REQUIRED_FALSE if invariants.get(name) is not False]
    if bad_invariants:
        errors.append("bad safety invariants: " + ", ".join(bad_invariants))

    make_text = read(MAKEFILE)
    security_text = read(SECURITY_CHECK)
    required_gate_names = [
        "osmap-v12-openpgp-inbound-security-state-gate.sh",
        "test-osmap-v12-openpgp-inbound-security-state-gate.sh",
    ]
    missing_make = [gate for gate in required_gate_names if gate not in make_text]
    if missing_make:
        errors.append("Makefile v12-check missing gates: " + ", ".join(missing_make))
    missing_security = [gate for gate in required_gate_names if gate not in security_text]
    if missing_security:
        errors.append("security-check missing gates: " + ", ".join(missing_security))

    refs = http_openpgp_references()
    if refs:
        errors.append("browser-facing http handlers reference OpenPGP inbound security-state code: " + ", ".join(refs))

    doc_text = read(DOC)
    required_doc_phrases = [
        "Verified does not mean safe",
        "Decrypted does not mean renderable",
        "existing secure rendering path",
        "does not implement helper spawning",
    ]
    missing_doc = [phrase for phrase in required_doc_phrases if phrase not in doc_text]
    if missing_doc:
        errors.append("inbound security-state document missing phrases: " + ", ".join(missing_doc))

    return errors, warnings, decisions


def report():
    errors, warnings, decisions = validate()
    cfg = json.loads(read(CFG)) if CFG.exists() else {}
    return {
        "schema": "osmap-v12-openpgp-inbound-security-state-report-v1",
        "state_model_status": "available" if not errors else "blocked",
        "purpose": "Define inbound OpenPGP message security-state outcomes without enabling runtime crypto.",
        "decision_count": len(decisions),
        "decisions": decisions,
        "safety_invariants": cfg.get("safety_invariants", {}),
        "valid": not errors,
        "warnings": warnings,
        "errors": errors,
    }


def main():
    if "--self-test" in sys.argv:
        errors, _warnings, decisions = validate()
        if errors:
            return fail("; ".join(errors))
        if len(decisions) < len(REQUIRED_CASE_NAMES):
            return fail("too few inbound security-state decisions")
        print("V12 OpenPGP inbound security-state model self-test passed")
        return 0
    data = report()
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
