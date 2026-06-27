#!/usr/bin/env python3
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "maint" / "security" / "v12-openpgp-capability-policy.example.json"
MAKEFILE = ROOT / "Makefile"
SECURITY_CHECK = ROOT / "maint" / "security" / "osmap-security-check.sh"
DOC = ROOT / "docs" / "V12_OPENPGP_CAPABILITY_POLICY_MODEL.md"
HTTP_DIR = ROOT / "src" / "http"
FPR_RE = re.compile(r"^[0-9A-F]{40}$|^[0-9A-F]{64}$")

REQUIRED_FALSE = [
    "browser_ui_integrated",
    "decrypted_content_rendering_enabled",
    "helper_process_spawned_by_slice",
    "key_discovery_enabled",
    "keyserver_lookup_enabled",
    "message_decryption_attempted",
    "message_encryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "passphrases_prompted_or_stored",
    "pgp_mime_parsing_attempted",
    "private_key_access_attempted",
    "signature_means_content_safe",
    "uid_text_trusted_for_key_selection",
    "wkd_lookup_enabled",
]

REQUIRED_STATE_NAMES = {
    "unavailable_no_account_key",
    "available_configured_fingerprint",
    "fail_closed_ambiguous_account_binding",
    "fail_closed_duplicate_account_binding",
    "fail_closed_recipient_key_missing",
    "signed_not_safe",
    "decrypted_still_hostile",
}


def fail(message):
    print(message, file=sys.stderr)
    return 1


def read(path):
    return path.read_text(encoding="utf-8")


def decide(state):
    enabled = bool(state.get("account_openpgp_enabled"))
    fps = state.get("configured_account_fingerprints", [])
    if not isinstance(fps, list):
        return "fail_closed", "bad_fingerprint_list"
    normalized = [str(f) for f in fps]
    if not enabled:
        if normalized:
            return "fail_closed", "disabled_account_has_fingerprints"
        return "unavailable", "no_openpgp_controls"
    if not normalized:
        return "unavailable", "no_openpgp_controls"
    if any(not FPR_RE.match(f) for f in normalized):
        return "fail_closed", "invalid_account_fingerprint"
    if len(set(normalized)) != len(normalized):
        return "fail_closed", "duplicate_account_binding"
    if len(normalized) != 1:
        return "fail_closed", "ambiguous_account_binding"
    if state.get("recipient_encryption_required") is True and state.get("recipient_key_policy_present") is not True:
        return "fail_closed", "recipient_key_policy_missing"
    if state.get("signature_status_available") is True:
        if state.get("content_treated_as_safe") is True:
            return "fail_closed", "signature_must_not_mark_content_safe"
        return "available", "signature_does_not_make_content_safe"
    if state.get("decryption_status_available") is True:
        if state.get("secure_rendering_required") is not True:
            return "fail_closed", "secure_rendering_not_required_for_decrypted_content"
        if state.get("content_treated_as_safe") is True:
            return "fail_closed", "decrypted_content_must_remain_hostile"
        return "available", "decrypted_content_requires_secure_rendering"
    return "available", "capability_available"


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
    if cfg.get("schema") != "osmap-v12-openpgp-capability-policy-v1":
        errors.append("unexpected schema")
    states = cfg.get("capability_states")
    if not isinstance(states, list) or not states:
        errors.append("capability_states must be a nonempty list")
        states = []

    names = {state.get("name") for state in states if isinstance(state, dict)}
    missing = sorted(REQUIRED_STATE_NAMES - names)
    if missing:
        errors.append("missing required capability states: " + ", ".join(missing))

    decisions = []
    for state in states:
        if not isinstance(state, dict):
            errors.append("capability state entry is not an object")
            continue
        name = state.get("name", "<unnamed>")
        capability, outcome = decide(state)
        decisions.append({"name": name, "capability": capability, "outcome": outcome})
        if capability != state.get("expected_capability"):
            errors.append(f"{name}: expected_capability mismatch: expected {state.get('expected_capability')} got {capability}")
        if outcome != state.get("expected_outcome"):
            errors.append(f"{name}: expected_outcome mismatch: expected {state.get('expected_outcome')} got {outcome}")

    invariants = cfg.get("safety_invariants", {})
    bad_invariants = [name for name in REQUIRED_FALSE if invariants.get(name) is not False]
    if bad_invariants:
        errors.append("bad safety invariants: " + ", ".join(bad_invariants))

    make_text = read(MAKEFILE)
    security_text = read(SECURITY_CHECK)
    required_gate_names = [
        "osmap-v12-openpgp-capability-policy-gate.sh",
        "test-osmap-v12-openpgp-capability-policy-gate.sh",
    ]
    missing_make = [gate for gate in required_gate_names if gate not in make_text]
    if missing_make:
        errors.append("Makefile v12-check missing gates: " + ", ".join(missing_make))
    missing_security = [gate for gate in required_gate_names if gate not in security_text]
    if missing_security:
        errors.append("security-check missing gates: " + ", ".join(missing_security))

    refs = http_openpgp_references()
    if refs:
        errors.append("browser-facing http handlers reference OpenPGP policy code: " + ", ".join(refs))

    doc_text = read(DOC)
    required_doc_phrases = [
        "decrypted content remains hostile",
        "signature",
        "does not make message content safe",
        "does not implement helper spawning",
    ]
    missing_doc = [phrase for phrase in required_doc_phrases if phrase not in doc_text]
    if missing_doc:
        errors.append("capability policy document missing phrases: " + ", ".join(missing_doc))

    return errors, warnings, decisions


def report():
    errors, warnings, decisions = validate()
    cfg = json.loads(read(CFG)) if CFG.exists() else {}
    return {
        "schema": "osmap-v12-openpgp-capability-policy-report-v1",
        "policy_status": "available" if not errors else "blocked",
        "purpose": "Define OpenPGP account capability and fail-closed policy outcomes without enabling runtime crypto.",
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
        if len(decisions) < len(REQUIRED_STATE_NAMES):
            return fail("too few capability decisions")
        print("V12 OpenPGP capability policy model self-test passed")
        return 0
    data = report()
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
