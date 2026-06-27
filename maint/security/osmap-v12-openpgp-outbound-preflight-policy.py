#!/usr/bin/env python3
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CFG = ROOT / "maint" / "security" / "v12-openpgp-outbound-preflight-policy.example.json"
MAKEFILE = ROOT / "Makefile"
SECURITY_CHECK = ROOT / "maint" / "security" / "osmap-security-check.sh"
DOC = ROOT / "docs" / "V12_OPENPGP_OUTBOUND_PREFLIGHT_POLICY.md"
HTTP_DIR = ROOT / "src" / "http"
FPR_RE = re.compile(r"^[0-9A-F]{40}$|^[0-9A-F]{64}$")

REQUIRED_FALSE = [
    "browser_ui_integrated",
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
    "recipient_email_text_trusted_for_key_selection",
    "sent_encrypted_mail_generation_enabled",
    "uid_text_trusted_for_key_selection",
    "wkd_lookup_enabled",
]

REQUIRED_CASE_NAMES = {
    "allow_required_all_recipient_keys_present",
    "fail_closed_missing_recipient_key_policy",
    "fail_closed_ambiguous_recipient_key_policy",
    "fail_closed_encrypt_to_self_sender_key_missing",
    "fail_closed_signing_requested_sender_signing_missing",
    "allow_unencrypted_send_by_account_policy",
    "fail_closed_unencrypted_send_disallowed",
}


def fail(message):
    print(message, file=sys.stderr)
    return 1


def read(path):
    return path.read_text(encoding="utf-8")


def valid_fingerprint(value):
    return bool(FPR_RE.match(str(value)))


def decide(case):
    sender = case.get("sender_account_policy", {})
    policy = case.get("send_policy", {})
    recipients = case.get("recipient_key_policies", [])
    encryption_required = policy.get("encryption_required") is True
    signing_requested = policy.get("signing_requested") is True
    encrypt_to_self_required = policy.get("encrypt_to_self_required") is True
    sender_fpr = str(sender.get("primary_fingerprint", ""))

    if signing_requested and sender.get("can_sign") is not True:
        return "fail_closed", "sender_signing_capability_missing"

    if not encryption_required:
        if policy.get("encrypt_to_self_required") is True:
            return "fail_closed", "encrypt_to_self_without_encryption_required"
        if signing_requested:
            if sender.get("can_sign") is True and valid_fingerprint(sender_fpr):
                return "allow", "unencrypted_signed_preflight_allowed"
            return "fail_closed", "sender_signing_capability_missing"
        if sender.get("unencrypted_send_permitted") is True:
            return "allow", "unencrypted_send_allowed_by_account_policy"
        return "fail_closed", "unencrypted_send_disallowed_by_account_policy"

    if sender.get("openpgp_enabled") is not True:
        return "fail_closed", "sender_openpgp_not_enabled"
    if not valid_fingerprint(sender_fpr):
        return "fail_closed", "sender_encrypt_to_self_key_missing" if encrypt_to_self_required else "sender_account_key_missing"
    if encrypt_to_self_required and sender.get("can_encrypt_to_self") is not True:
        return "fail_closed", "sender_encrypt_to_self_key_missing"
    if not isinstance(recipients, list) or not recipients:
        return "fail_closed", "recipient_key_policy_missing"
    for recipient in recipients:
        fps = recipient.get("configured_fingerprints") if isinstance(recipient, dict) else None
        if not isinstance(fps, list) or not fps:
            return "fail_closed", "recipient_key_policy_missing"
        normalized = [str(f) for f in fps]
        if any(not valid_fingerprint(f) for f in normalized):
            return "fail_closed", "invalid_recipient_fingerprint"
        if len(set(normalized)) != len(normalized):
            return "fail_closed", "duplicate_recipient_key_policy"
        if len(normalized) != 1:
            return "fail_closed", "ambiguous_recipient_key_policy"
    return "allow", "encryption_preflight_allowed"


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
    if cfg.get("schema") != "osmap-v12-openpgp-outbound-preflight-policy-v1":
        errors.append("unexpected schema")
    cases = cfg.get("preflight_cases")
    if not isinstance(cases, list) or not cases:
        errors.append("preflight_cases must be a nonempty list")
        cases = []

    names = {case.get("name") for case in cases if isinstance(case, dict)}
    missing = sorted(REQUIRED_CASE_NAMES - names)
    if missing:
        errors.append("missing required preflight cases: " + ", ".join(missing))

    decisions = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("preflight case entry is not an object")
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
        "osmap-v12-openpgp-outbound-preflight-policy-gate.sh",
        "test-osmap-v12-openpgp-outbound-preflight-policy-gate.sh",
    ]
    missing_make = [gate for gate in required_gate_names if gate not in make_text]
    if missing_make:
        errors.append("Makefile v12-check missing gates: " + ", ".join(missing_make))
    missing_security = [gate for gate in required_gate_names if gate not in security_text]
    if missing_security:
        errors.append("security-check missing gates: " + ", ".join(missing_security))

    refs = http_openpgp_references()
    if refs:
        errors.append("browser-facing http handlers reference OpenPGP outbound preflight code: " + ", ".join(refs))

    doc_text = read(DOC)
    required_doc_phrases = [
        "Recipient keys are policy objects",
        "does not perform encryption",
        "does not implement helper spawning",
        "sent encrypted mail generation",
    ]
    missing_doc = [phrase for phrase in required_doc_phrases if phrase not in doc_text]
    if missing_doc:
        errors.append("outbound preflight document missing phrases: " + ", ".join(missing_doc))

    return errors, warnings, decisions


def report():
    errors, warnings, decisions = validate()
    cfg = json.loads(read(CFG)) if CFG.exists() else {}
    return {
        "schema": "osmap-v12-openpgp-outbound-preflight-policy-report-v1",
        "policy_status": "available" if not errors else "blocked",
        "purpose": "Define outbound OpenPGP preflight policy outcomes without enabling runtime crypto.",
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
            return fail("too few outbound preflight decisions")
        print("V12 OpenPGP outbound preflight policy model self-test passed")
        return 0
    data = report()
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
