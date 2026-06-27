#!/usr/bin/env python3
"""Validate the OSMAP V12 OpenPGP GPGME helper compile scaffold.

This tool performs metadata and compile/link checks only. It must not perform
OpenPGP message operations.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

SCHEMA = "osmap-v12-openpgp-helper-compile-scaffold-v1"
REPORT_SCHEMA = "osmap-v12-openpgp-helper-compile-scaffold-report-v1"

TRUE_REQUIRED = {
    "preferred_runtime_binding_is_gpgme",
    "gpgme_metadata_required",
    "compile_and_link_probe_required",
    "unknown_operations_fail_closed",
    "account_binding_required_before_runtime_crypto",
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

GPGME_OP = "gpgme_op_"
GPGME_GET = "gpgme_get_"
COMMAND_NEW = "Command::" + "new"
STD_PROCESS_COMMAND = "std::process::" + "Command"
GPG_RUNTIME_PREFIX = "gpg --"

DEFAULT_FORBIDDEN_PATTERNS = [
    GPGME_OP + "decrypt",
    GPGME_OP + "verify",
    GPGME_OP + "sign",
    GPGME_OP + "encrypt",
    GPGME_GET + "key",
    GPGME_GET + "keylist",
    GPGME_OP + "keylist",
    "gpgme_set_" + "passphrase_cb",
    COMMAND_NEW,
    STD_PROCESS_COMMAND,
    GPG_RUNTIME_PREFIX + "decrypt",
    GPG_RUNTIME_PREFIX + "sign",
    GPG_RUNTIME_PREFIX + "encrypt",
    GPG_RUNTIME_PREFIX + "verify",
]

TRUE_SCANNER_RULES = {
    "reject_gpgme_message_operations",
    "reject_key_lookup_operations",
    "reject_passphrase_callback",
    "reject_process_command_fallbacks",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_probe(argv: list[str]) -> dict[str, Any]:
    executable_found = shutil.which(argv[0]) is not None
    if not executable_found:
        return {
            "argv": argv,
            "executable_found": False,
            "exit_status": None,
            "stdout_first_line": "",
            "stderr_first_line": "",
        }
    completed = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {
        "argv": argv,
        "executable_found": True,
        "exit_status": completed.returncode,
        "stdout_first_line": completed.stdout.splitlines()[0] if completed.stdout.splitlines() else "",
        "stderr_first_line": completed.stderr.splitlines()[0] if completed.stderr.splitlines() else "",
    }


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
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
    source_path = data.get("source_path")
    if not isinstance(source_path, str) or not source_path:
        errors.append("source_path must be a non-empty string")

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

    scanner = data.get("source_scanner")
    if not isinstance(scanner, dict):
        errors.append("source_scanner must be an object")
    else:
        for key in sorted(TRUE_SCANNER_RULES):
            if scanner.get(key) is not True:
                errors.append(f"source_scanner.{key} must be true")
    return errors


def scan_source(source_path: pathlib.Path, forbidden_patterns: list[str]) -> list[str]:
    errors: list[str] = []
    try:
        source = source_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [f"cannot read source_path {source_path}: {exc}"]
    if "#include <gpgme.h>" not in source:
        errors.append("helper scaffold source must include <gpgme.h>")
    if "gpgme_check_version" not in source:
        errors.append("helper scaffold source must reference gpgme_check_version for link proof")
    for pattern in forbidden_patterns:
        if pattern in source:
            errors.append(f"forbidden source pattern present: {pattern}")
    return errors


def compile_link_probe(source_path: pathlib.Path) -> dict[str, Any]:
    pkg_cflags = run_probe(["pkg-config", "--cflags", "gpgme"])
    pkg_libs = run_probe(["pkg-config", "--libs", "gpgme"])
    if pkg_cflags["exit_status"] != 0 or pkg_libs["exit_status"] != 0:
        return {
            "attempted": False,
            "available": False,
            "exit_status": None,
            "stdout_first_line": "",
            "stderr_first_line": "pkg-config gpgme metadata unavailable",
            "argv": [],
        }
    cflags = pkg_cflags["stdout_first_line"].split()
    libs = pkg_libs["stdout_first_line"].split()
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory(prefix="osmap-v12-openpgp-helper-compile-") as tmp:
        output = pathlib.Path(tmp) / "osmap-openpgp-helper-compile-only"
        argv = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", *cflags, str(source_path), "-o", str(output), *libs]
        completed = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return {
            "attempted": True,
            "available": completed.returncode == 0,
            "exit_status": completed.returncode,
            "stdout_first_line": completed.stdout.splitlines()[0] if completed.stdout.splitlines() else "",
            "stderr_first_line": completed.stderr.splitlines()[0] if completed.stderr.splitlines() else "",
            "argv": argv,
        }


def build_report(config_path: pathlib.Path, source_override: str | None, skip_compile: bool) -> tuple[dict[str, Any], int]:
    data = load_json(config_path)
    errors = validate_config(data)
    source_path = pathlib.Path(source_override or data.get("source_path", ""))
    forbidden_patterns = DEFAULT_FORBIDDEN_PATTERNS

    source_errors = scan_source(source_path, forbidden_patterns)
    errors.extend(source_errors)

    probes = {
        "gpg_version": run_probe(["gpg", "--version"]),
        "pkg_config_gpgme_modversion": run_probe(["pkg-config", "--modversion", "gpgme"]),
        "pkg_config_gpgme_cflags_libs": run_probe(["pkg-config", "--cflags", "--libs", "gpgme"]),
    }
    gpgme_metadata_available = probes["pkg_config_gpgme_modversion"]["exit_status"] == 0 and probes["pkg_config_gpgme_cflags_libs"]["exit_status"] == 0

    compile_probe = {
        "attempted": False,
        "available": False,
        "exit_status": None,
        "stdout_first_line": "",
        "stderr_first_line": "skipped",
        "argv": [],
    }
    if not skip_compile and not source_errors:
        compile_probe = compile_link_probe(source_path)
    if not gpgme_metadata_available:
        errors.append("pkg-config gpgme metadata is required")
    if not skip_compile and not compile_probe.get("available"):
        errors.append("helper scaffold compile/link probe failed")

    report = {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": utc_now(),
        "purpose": "Prove V12 OpenPGP helper compile scaffold can link against GPGME without enabling runtime crypto.",
        "config_path": str(config_path),
        "source_path": str(source_path),
        "helper_name": data.get("helper_name"),
        "compile_scaffold_status": "available" if not errors else "failed",
        "environment": {
            "gpg_available": probes["gpg_version"]["exit_status"] == 0,
            "pkg_config_gpgme_available": gpgme_metadata_available,
            "compile_or_link_probe": compile_probe,
            "probes": probes,
        },
        "safety_invariants": data.get("safety_invariants", {}),
        "forbidden_source_patterns_checked": forbidden_patterns,
        "errors": errors,
        "warnings": [],
        "valid": not errors,
        "next_required_action": "Proceed to a protocol-only helper invocation slice; runtime crypto remains disabled.",
    }
    return report, 0 if not errors else 1


def self_test() -> int:
    good = {
        "schema": SCHEMA,
        "helper_name": "osmap-openpgp-helper",
        "source_path": "unused.c",
        "required": {key: True for key in TRUE_REQUIRED},
        "safety_invariants": {key: False for key in FALSE_INVARIANTS},
        "source_scanner": {key: True for key in TRUE_SCANNER_RULES},
    }
    assert validate_config(good) == []
    bad = json.loads(json.dumps(good))
    bad["safety_invariants"]["runtime_crypto_enabled"] = True
    assert any("runtime_crypto_enabled" in err for err in validate_config(bad))
    with tempfile.TemporaryDirectory(prefix="osmap-v12-helper-scaffold-test-") as tmp:
        src = pathlib.Path(tmp) / "bad.c"
        bad_call = GPGME_OP + "decrypt"
        src.write_text(f"#include <gpgme.h>\nint main(void){{{bad_call}(0,0,0);return 0;}}\n", encoding="utf-8")
        assert any(bad_call in err for err in scan_source(src, DEFAULT_FORBIDDEN_PATTERNS))
    print("V12 OpenPGP helper compile scaffold self-test passed")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="maint/security/v12-openpgp-helper-compile-scaffold.example.json")
    parser.add_argument("--source")
    parser.add_argument("--report")
    parser.add_argument("--skip-compile", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    report, status = build_report(pathlib.Path(args.config), args.source, args.skip_compile)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        pathlib.Path(args.report).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
