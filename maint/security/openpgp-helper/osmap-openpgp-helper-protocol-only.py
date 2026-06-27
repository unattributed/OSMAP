#!/usr/bin/env python3
"""Protocol-only OSMAP OpenPGP helper scaffold.

This helper exists only to prove bounded JSON invocation behavior. It does not
perform OpenPGP message operations and does not inspect private key material.
"""
from __future__ import annotations

import json
import sys
from typing import Any

MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 8192
ALLOWED_OPERATIONS = {"diagnostic_ping", "capability_status", "policy_check"}


def emit(payload: dict[str, Any], status: int) -> int:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    if len(rendered.encode("utf-8")) > MAX_RESPONSE_BYTES:
        fallback = {"ok": False, "error_code": "response_too_large", "runtime_crypto_enabled": False}
        rendered = json.dumps(fallback, sort_keys=True, separators=(",", ":")) + "\n"
        status = 2
    sys.stdout.write(rendered)
    return status


def fail(error_code: str, status: int = 2) -> int:
    return emit({"ok": False, "error_code": error_code, "runtime_crypto_enabled": False}, status)


def handle(request: dict[str, Any]) -> tuple[dict[str, Any], int]:
    operation = request.get("operation")
    if not isinstance(operation, str) or not operation:
        return {"ok": False, "error_code": "missing_operation", "runtime_crypto_enabled": False}, 2
    if operation not in ALLOWED_OPERATIONS:
        return {
            "ok": False,
            "operation": operation,
            "error_code": "unsupported_operation",
            "runtime_crypto_enabled": False,
        }, 2
    if operation == "diagnostic_ping":
        return {
            "ok": True,
            "operation": operation,
            "response": "pong",
            "runtime_crypto_enabled": False,
        }, 0
    if operation == "capability_status":
        return {
            "ok": True,
            "operation": operation,
            "helper_protocol": "osmap-v12-openpgp-helper-protocol-only-v1",
            "supported_operations": sorted(ALLOWED_OPERATIONS),
            "gpgme_required_for_future_crypto": True,
            "runtime_crypto_enabled": False,
        }, 0
    if operation == "policy_check":
        account_fingerprint = request.get("account_fingerprint")
        account_binding_present = isinstance(account_fingerprint, str) and len(account_fingerprint) in {40, 64}
        return {
            "ok": True,
            "operation": operation,
            "account_binding_present": account_binding_present,
            "policy_decision": "runtime_crypto_disabled",
            "runtime_crypto_enabled": False,
        }, 0
    return {"ok": False, "error_code": "unreachable", "runtime_crypto_enabled": False}, 2


def main(argv: list[str]) -> int:
    if argv != ["--protocol-only"]:
        return fail("invalid_argv")
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return fail("request_too_large")
    try:
        request = json.loads(raw.decode("utf-8"))
    except Exception:
        return fail("malformed_json")
    if not isinstance(request, dict):
        return fail("request_not_object")
    response, status = handle(request)
    return emit(response, status)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
