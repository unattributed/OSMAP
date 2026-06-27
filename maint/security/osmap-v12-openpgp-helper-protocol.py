#!/usr/bin/env python3
"""Validate the V12 OpenPGP helper protocol scaffold.

This validator is intentionally non-cryptographic. It validates the protocol
contract that later helper implementation slices must consume. It must not call
GPGME, gpg, or any OpenPGP operation.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "osmap-v12-openpgp-helper-protocol-v1"
REPORT_SCHEMA = "osmap-v12-openpgp-helper-protocol-report-v1"
ALLOWED_OPERATIONS = {"capability_status", "policy_check", "diagnostic_ping"}
CRYPTO_OPERATION_PATTERNS = (
    "decrypt",
    "encrypt",
    "sign",
    "verify",
    "clearsign",
    "detach-sign",
    "export-secret",
    "list-secret",
    "import-key",
)
FORBIDDEN_FIELD_HINTS = (
    "plaintext",
    "decrypted_body",
    "message_body",
    "raw_message",
    "private_key",
    "secret_key",
    "passphrase",
    "signed_body",
    "trusted_html",
)


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def is_bool_true(mapping: dict[str, Any], key: str, errors: list[str]) -> None:
    if mapping.get(key) is not True:
        errors.append(f"{key} must be true")


def is_bool_false(mapping: dict[str, Any], key: str, errors: list[str]) -> None:
    if mapping.get(key) is not False:
        errors.append(f"{key} must be false")


def validate_protocol(config: dict[str, Any], config_path: str) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if config.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")

    if config.get("helper_name") != "osmap-openpgp-helper":
        errors.append("helper_name must be osmap-openpgp-helper")

    operations = config.get("allowed_operations")
    if not isinstance(operations, list) or not operations:
        errors.append("allowed_operations must be a non-empty list")
        operations = []

    operation_set = set()
    for operation in operations:
        if not isinstance(operation, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", operation):
            errors.append(f"invalid operation name: {operation!r}")
            continue
        operation_set.add(operation)
        lowered = operation.lower()
        if any(pattern in lowered for pattern in CRYPTO_OPERATION_PATTERNS):
            errors.append(f"cryptographic operation is not allowed in Slice 4: {operation}")

    if operation_set != ALLOWED_OPERATIONS:
        errors.append(
            "allowed_operations must exactly match the Slice 4 non-cryptographic scaffold set: "
            + ", ".join(sorted(ALLOWED_OPERATIONS))
        )

    request = config.get("request_boundary")
    if not isinstance(request, dict):
        errors.append("request_boundary must be an object")
        request = {}
    for key in (
        "requires_request_id",
        "requires_account",
        "requires_validated_account_binding",
        "requires_full_fingerprint_for_key_scoped_operations",
        "rejects_short_key_ids",
        "rejects_email_only_key_matching",
        "rejects_uid_text_authorization",
        "unknown_operations_fail_closed",
    ):
        is_bool_true(request, key, errors)
    if request.get("message_material_transport") != "opaque-reference-or-digest-only":
        errors.append("message_material_transport must be opaque-reference-or-digest-only")

    response = config.get("response_boundary")
    if not isinstance(response, dict):
        errors.append("response_boundary must be an object")
        response = {}
    if set(response.get("bounded_status_values", [])) != {"ok", "rejected", "unavailable"}:
        errors.append("bounded_status_values must be exactly ok, rejected, unavailable")
    is_bool_true(response, "redacted_error_required", errors)
    for key in (
        "browser_trusted_html_allowed",
        "message_body_return_allowed",
        "private_key_material_return_allowed",
        "passphrase_return_allowed",
    ):
        is_bool_false(response, key, errors)

    logging = config.get("logging_boundary")
    if not isinstance(logging, dict):
        errors.append("logging_boundary must be an object")
        logging = {}
    for key in (
        "log_plaintext_message_body",
        "log_decrypted_message_body",
        "log_passphrase",
        "log_private_key_material",
        "log_uid_values",
        "log_full_raw_message",
        "log_full_request_payload",
    ):
        is_bool_false(logging, key, errors)

    invariants = config.get("safety_invariants")
    if not isinstance(invariants, dict):
        errors.append("safety_invariants must be an object")
        invariants = {}
    for key in (
        "message_decryption_implemented",
        "message_signature_verification_implemented",
        "message_signing_implemented",
        "message_encryption_implemented",
        "pgp_mime_parsing_implemented",
        "gpgme_runtime_invoked",
        "secret_key_access_attempted",
        "passphrases_prompted_or_stored",
        "browser_request_handler_touched_keys",
    ):
        is_bool_false(invariants, key, errors)
    for key in ("account_binding_required", "unknown_operation_fails_closed"):
        is_bool_true(invariants, key, errors)

    serialized = json.dumps(config, sort_keys=True).lower()
    # The scaffold may name forbidden concepts only as explicit false logging or
    # response boundaries. This check verifies none are accidentally introduced
    # as top-level protocol fields or allowed operation names.
    for field_hint in FORBIDDEN_FIELD_HINTS:
        field_pattern = f'"{field_hint}"'
        if field_pattern in serialized:
            errors.append(f"forbidden protocol field present: {field_hint}")

    report = {
        "schema": REPORT_SCHEMA,
        "config_path": config_path,
        "generated_at_utc": now_utc(),
        "purpose": "Validate the V12 OpenPGP helper protocol scaffold before cryptographic helper integration.",
        "allowed_operations": sorted(operation_set),
        "errors": errors,
        "warnings": warnings,
        "safety_invariants": {
            "message_decryption_attempted": False,
            "message_signature_verification_attempted": False,
            "message_signing_attempted": False,
            "message_encryption_attempted": False,
            "gpgme_runtime_invoked": False,
            "secret_key_access_attempted": False,
            "passphrases_prompted_or_stored": False,
            "browser_request_handler_touched_keys": False,
            "account_binding_required": invariants.get("account_binding_required") is True,
            "unknown_operation_fails_closed": invariants.get("unknown_operation_fails_closed") is True,
        },
        "next_required_boundary": "Later helper implementation must preserve this protocol and add GPGME operations only behind validated account fingerprints and redacted evidence.",
        "valid": not errors,
    }
    return report


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def expect_invalid(config: dict[str, Any], expected_fragment: str) -> None:
    report = validate_protocol(config, "self-test.json")
    if report["valid"]:
        raise AssertionError(f"expected invalid protocol containing {expected_fragment!r}")
    joined = "\n".join(report["errors"])
    if expected_fragment not in joined:
        raise AssertionError(f"expected {expected_fragment!r} in errors, got: {joined}")


def good_config() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "helper_name": "osmap-openpgp-helper",
        "purpose": "self-test",
        "allowed_operations": ["capability_status", "policy_check", "diagnostic_ping"],
        "request_boundary": {
            "requires_request_id": True,
            "requires_account": True,
            "requires_validated_account_binding": True,
            "requires_full_fingerprint_for_key_scoped_operations": True,
            "rejects_short_key_ids": True,
            "rejects_email_only_key_matching": True,
            "rejects_uid_text_authorization": True,
            "unknown_operations_fail_closed": True,
            "message_material_transport": "opaque-reference-or-digest-only",
        },
        "response_boundary": {
            "bounded_status_values": ["ok", "rejected", "unavailable"],
            "redacted_error_required": True,
            "browser_trusted_html_allowed": False,
            "message_body_return_allowed": False,
            "private_key_material_return_allowed": False,
            "passphrase_return_allowed": False,
        },
        "logging_boundary": {
            "log_plaintext_message_body": False,
            "log_decrypted_message_body": False,
            "log_passphrase": False,
            "log_private_key_material": False,
            "log_uid_values": False,
            "log_full_raw_message": False,
            "log_full_request_payload": False,
        },
        "safety_invariants": {
            "message_decryption_implemented": False,
            "message_signature_verification_implemented": False,
            "message_signing_implemented": False,
            "message_encryption_implemented": False,
            "pgp_mime_parsing_implemented": False,
            "gpgme_runtime_invoked": False,
            "secret_key_access_attempted": False,
            "passphrases_prompted_or_stored": False,
            "browser_request_handler_touched_keys": False,
            "account_binding_required": True,
            "unknown_operation_fails_closed": True,
        },
    }


def run_self_test() -> None:
    good = good_config()
    report = validate_protocol(good, "self-test-good.json")
    if not report["valid"]:
        raise AssertionError(f"good config failed validation: {report['errors']}")

    bad_op = json.loads(json.dumps(good))
    bad_op["allowed_operations"].append("decrypt_message")
    expect_invalid(bad_op, "cryptographic operation is not allowed")

    bad_unknown = json.loads(json.dumps(good))
    bad_unknown["request_boundary"]["unknown_operations_fail_closed"] = False
    expect_invalid(bad_unknown, "unknown_operations_fail_closed")

    bad_binding = json.loads(json.dumps(good))
    bad_binding["request_boundary"]["requires_validated_account_binding"] = False
    expect_invalid(bad_binding, "requires_validated_account_binding")

    bad_secret = json.loads(json.dumps(good))
    bad_secret["safety_invariants"]["secret_key_access_attempted"] = True
    expect_invalid(bad_secret, "secret_key_access_attempted")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "good.json"
        write_json(path, good)
        loaded = load_json(path)
        loaded_report = validate_protocol(loaded, str(path))
        if not loaded_report["valid"]:
            raise AssertionError("round-trip validation failed")

    print("V12 OpenPGP helper protocol self-test passed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Protocol definition JSON to validate")
    parser.add_argument("--output", help="Optional report output path")
    parser.add_argument("--self-test", action="store_true", help="Run built-in validation tests")
    args = parser.parse_args(argv)

    if args.self_test:
        run_self_test()
        return 0

    if not args.config:
        parser.error("--config is required unless --self-test is used")

    config_path = Path(args.config)
    config = load_json(config_path)
    if not isinstance(config, dict):
        raise SystemExit("config root must be an object")
    report = validate_protocol(config, str(config_path))

    if args.output:
        write_json(Path(args.output), report)
    else:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")

    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
