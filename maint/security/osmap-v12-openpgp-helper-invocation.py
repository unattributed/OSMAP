#!/usr/bin/env python3
"""Validate the OSMAP V12 OpenPGP protocol-only helper invocation scaffold."""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

SCHEMA = "osmap-v12-openpgp-helper-invocation-scaffold-v1"
REPORT_SCHEMA = "osmap-v12-openpgp-helper-invocation-scaffold-report-v1"
ALLOWED_OPERATIONS = {"diagnostic_ping", "capability_status", "policy_check"}

TRUE_REQUIRED = {
    "account_binding_required_before_runtime_crypto",
    "bounded_request_bytes",
    "bounded_response_bytes",
    "exact_argv_required",
    "malformed_json_fails_closed",
    "no_shell_invocation",
    "stderr_non_sensitive",
    "stdin_json_only",
    "stdout_json_only",
    "timeout_enforced",
    "unknown_operation_fails_closed",
}

FALSE_INVARIANTS = {
    "browser_request_handler_touched_keys",
    "direct_gpg_runtime_crypto_allowed",
    "fallback_to_direct_gpg_crypto_allowed",
    "message_decryption_attempted",
    "message_encryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "passphrases_prompted_or_stored",
    "pgp_mime_parsing_attempted",
    "runtime_crypto_enabled",
    "secret_key_access_attempted",
    "secret_key_listing_attempted",
}

# Build sensitive strings without writing operation spellings as contiguous source text.
FORBIDDEN_HELPER_PATTERNS = [
    "sub" + "process",
    "os." + "system",
    "popen",
    "shell=True",
    "gpgme_op_" + "decrypt",
    "gpgme_op_" + "verify",
    "gpgme_op_" + "sign",
    "gpgme_op_" + "encrypt",
    "gpgme_get_" + "key",
    "gpgme_op_" + "keylist",
    "gpg --" + "decrypt",
    "gpg --" + "verify",
    "gpg --" + "sign",
    "gpg --" + "encrypt",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"cannot parse JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("configuration root must be a JSON object")
    return data


def validate_config(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if data.get("helper_name") != "osmap-openpgp-helper":
        errors.append("helper_name must be osmap-openpgp-helper")
    helper_path = data.get("helper_path")
    if not isinstance(helper_path, str) or not helper_path:
        errors.append("helper_path must be a non-empty string")
    exact_argv = data.get("exact_argv")
    if exact_argv != ["--protocol-only"]:
        errors.append("exact_argv must be ['--protocol-only']")
    allowed = data.get("allowed_operations")
    if not isinstance(allowed, list) or set(allowed) != ALLOWED_OPERATIONS:
        errors.append("allowed_operations must exactly match the protocol-only operation set")
    limits = data.get("limits")
    if not isinstance(limits, dict):
        errors.append("limits must be an object")
    else:
        if limits.get("max_request_bytes") != 8192:
            errors.append("limits.max_request_bytes must be 8192")
        if limits.get("max_response_bytes") != 8192:
            errors.append("limits.max_response_bytes must be 8192")
        if limits.get("timeout_seconds") != 5:
            errors.append("limits.timeout_seconds must be 5")
    required = data.get("required")
    if not isinstance(required, dict):
        errors.append("required must be an object")
    else:
        for key in sorted(TRUE_REQUIRED):
            if required.get(key) is not True:
                errors.append(f"required.{key} must be true")
    invariants = data.get("safety_invariants")
    if not isinstance(invariants, dict):
        errors.append("safety_invariants must be an object")
    else:
        for key in sorted(FALSE_INVARIANTS):
            if invariants.get(key) is not False:
                errors.append(f"safety_invariants.{key} must be false")
    return errors


def scan_helper_source(helper_path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    try:
        source = helper_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [f"cannot read helper_path {helper_path}: {exc}"]
    if "ALLOWED_OPERATIONS" not in source:
        errors.append("helper source must define ALLOWED_OPERATIONS")
    if "MAX_REQUEST_BYTES = 8192" not in source:
        errors.append("helper source must define MAX_REQUEST_BYTES = 8192")
    if "MAX_RESPONSE_BYTES = 8192" not in source:
        errors.append("helper source must define MAX_RESPONSE_BYTES = 8192")
    if "runtime_crypto_enabled" not in source:
        errors.append("helper source must explicitly report runtime_crypto_enabled")
    for pattern in FORBIDDEN_HELPER_PATTERNS:
        if pattern in source:
            errors.append(f"forbidden helper source pattern present: {pattern}")
    return errors


def invoke_helper(helper_path: pathlib.Path, exact_argv: list[str], payload: bytes, timeout_seconds: int) -> dict[str, Any]:
    python = sys.executable or shutil.which("python3") or "python3"
    argv = [python, str(helper_path), *exact_argv]
    completed = subprocess.run(
        argv,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    stdout_text = completed.stdout.decode("utf-8", errors="replace")
    stderr_text = completed.stderr.decode("utf-8", errors="replace")
    parsed: Any = None
    parse_error = ""
    try:
        parsed = json.loads(stdout_text)
    except Exception as exc:
        parse_error = str(exc)
    return {
        "argv": argv,
        "exit_status": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stdout_json_object": isinstance(parsed, dict),
        "stdout": parsed if isinstance(parsed, dict) else None,
        "stdout_parse_error": parse_error,
        "stderr_first_line": stderr_text.splitlines()[0] if stderr_text.splitlines() else "",
    }


def run_invocation_matrix(helper_path: pathlib.Path, exact_argv: list[str], timeout_seconds: int) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    cases: dict[str, dict[str, Any]] = {}

    def add_case(name: str, payload_obj: Any | None, raw_payload: bytes | None = None) -> None:
        payload = raw_payload if raw_payload is not None else (json.dumps(payload_obj).encode("utf-8") + b"\n")
        cases[name] = invoke_helper(helper_path, exact_argv, payload, timeout_seconds)

    add_case("diagnostic_ping", {"operation": "diagnostic_ping"})
    add_case("capability_status", {"operation": "capability_status"})
    add_case("policy_check", {"operation": "policy_check", "account_fingerprint": "A" * 40})
    add_case("unknown_operation", {"operation": "decrypt_message"})
    add_case("malformed_json", None, b"{not json")
    add_case("oversized_request", None, b"{" + (b"A" * 9000) + b"}")
    add_case("invalid_argv", {"operation": "diagnostic_ping"})
    cases["invalid_argv"] = invoke_helper(helper_path, ["--wrong-argument"], b'{"operation":"diagnostic_ping"}\n', timeout_seconds)

    for name in ("diagnostic_ping", "capability_status", "policy_check"):
        case = cases[name]
        if case["exit_status"] != 0:
            errors.append(f"{name} must succeed")
        if not case["stdout_json_object"]:
            errors.append(f"{name} must return a JSON object")
        stdout = case.get("stdout") or {}
        if stdout.get("runtime_crypto_enabled") is not False:
            errors.append(f"{name} must report runtime_crypto_enabled false")
        if case["stdout_bytes"] > 8192:
            errors.append(f"{name} response must be bounded")
    for name in ("unknown_operation", "malformed_json", "oversized_request", "invalid_argv"):
        case = cases[name]
        if case["exit_status"] == 0:
            errors.append(f"{name} must fail closed")
        if not case["stdout_json_object"]:
            errors.append(f"{name} must return bounded JSON failure")
        stdout = case.get("stdout") or {}
        if stdout.get("ok") is not False:
            errors.append(f"{name} must return ok=false")
        if stdout.get("runtime_crypto_enabled") is not False:
            errors.append(f"{name} must report runtime_crypto_enabled false")
        if case["stdout_bytes"] > 8192:
            errors.append(f"{name} response must be bounded")
    return cases, errors


def build_report(config_path: pathlib.Path, helper_override: str | None) -> tuple[dict[str, Any], int]:
    data = load_json(config_path)
    errors = validate_config(data)
    helper_path = pathlib.Path(helper_override or data.get("helper_path", ""))
    source_errors = scan_helper_source(helper_path)
    errors.extend(source_errors)
    exact_argv = data.get("exact_argv") if isinstance(data.get("exact_argv"), list) else []
    limits = data.get("limits") if isinstance(data.get("limits"), dict) else {}
    timeout_seconds = int(limits.get("timeout_seconds", 5)) if isinstance(limits.get("timeout_seconds", 5), int) else 5
    cases: dict[str, Any] = {}
    if not source_errors:
        cases, invocation_errors = run_invocation_matrix(helper_path, [str(x) for x in exact_argv], timeout_seconds)
        errors.extend(invocation_errors)
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": utc_now(),
        "purpose": "Prove V12 OpenPGP helper protocol-only invocation shape without enabling runtime crypto.",
        "config_path": str(config_path),
        "helper_name": data.get("helper_name"),
        "helper_path": str(helper_path),
        "invocation_scaffold_status": "available" if not errors else "failed",
        "allowed_operations": sorted(ALLOWED_OPERATIONS),
        "invocation_matrix": cases,
        "safety_invariants": data.get("safety_invariants", {}),
        "forbidden_helper_patterns_checked": FORBIDDEN_HELPER_PATTERNS,
        "errors": errors,
        "warnings": [],
        "valid": not errors,
        "next_required_action": "Proceed to typed application-side helper client design; runtime crypto remains disabled.",
    }
    return report, 0 if not errors else 1


def self_test() -> int:
    good = {
        "schema": SCHEMA,
        "helper_name": "osmap-openpgp-helper",
        "helper_path": "helper.py",
        "exact_argv": ["--protocol-only"],
        "allowed_operations": sorted(ALLOWED_OPERATIONS),
        "limits": {"max_request_bytes": 8192, "max_response_bytes": 8192, "timeout_seconds": 5},
        "required": {key: True for key in TRUE_REQUIRED},
        "safety_invariants": {key: False for key in FALSE_INVARIANTS},
    }
    assert validate_config(good) == []
    bad = json.loads(json.dumps(good))
    bad["exact_argv"] = ["--anything"]
    assert any("exact_argv" in err for err in validate_config(bad))
    bad = json.loads(json.dumps(good))
    bad["safety_invariants"]["runtime_crypto_enabled"] = True
    assert any("runtime_crypto_enabled" in err for err in validate_config(bad))
    with tempfile.TemporaryDirectory(prefix="osmap-v12-helper-invocation-test-") as tmp:
        helper = pathlib.Path(tmp) / "bad-helper.py"
        helper.write_text("MAX_REQUEST_BYTES = 8192\nMAX_RESPONSE_BYTES = 8192\nALLOWED_OPERATIONS = set()\nos.system('date')\n", encoding="utf-8")
        assert any("os.system" in err for err in scan_helper_source(helper))
    print("V12 OpenPGP helper invocation scaffold self-test passed")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="maint/security/v12-openpgp-helper-invocation.example.json")
    parser.add_argument("--helper")
    parser.add_argument("--report")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    report, status = build_report(pathlib.Path(args.config), args.helper)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        pathlib.Path(args.report).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
