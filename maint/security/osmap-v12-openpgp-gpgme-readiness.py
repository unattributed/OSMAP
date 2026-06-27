#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "osmap-v12-openpgp-gpgme-readiness-policy-v1"
REPORT_SCHEMA = "osmap-v12-openpgp-gpgme-readiness-report-v1"
DEFAULT_CONFIG = Path("maint/security/v12-openpgp-gpgme-readiness.example.json")

EXPECTED_FALSE_POLICY = {
    "allow_direct_gpg_runtime_for_crypto_operations": "direct gpg runtime crypto fallback is not allowed",
    "allow_crypto_operations_in_slice5": "Slice 5 must not enable cryptographic operations",
    "allow_secret_key_listing_in_slice5": "Slice 5 must not list secret keys",
    "allow_passphrase_prompting_in_slice5": "Slice 5 must not prompt for passphrases",
    "allow_browser_handler_key_access_in_slice5": "Slice 5 must not allow browser request handlers to access keys",
}

EXPECTED_TRUE_POLICY = {
    "require_gpgme_for_crypto_operations": "future cryptographic operations must require GPGME readiness",
}

ALLOWED_METADATA_PROBES = {
    "gpg --version",
    "gpgme-config --version",
    "pkg-config --modversion gpgme",
    "pkg-config --cflags --libs gpgme",
}

FORBIDDEN_PROBE_TOKENS = (
    "--decrypt",
    "--encrypt",
    "--sign",
    "--clearsign",
    "--detach-sign",
    "--verify",
    "--list-secret-keys",
    "--export-secret-keys",
    "--edit-key",
    "--delete-secret-keys",
    "--import",
    "--receive-keys",
    "--send-keys",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"missing config: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid json in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("config must be a JSON object")
    return data


def run_metadata_probe(argv: list[str]) -> dict[str, Any]:
    exe = shutil.which(argv[0])
    result: dict[str, Any] = {
        "argv": argv,
        "executable_found": exe is not None,
        "exit_status": None,
        "stdout_first_line": "",
        "stderr_first_line": "",
    }
    if exe is None:
        return result
    try:
        completed = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except Exception as exc:  # pragma: no cover - defensive metadata path
        result["error"] = type(exc).__name__
        return result
    result["exit_status"] = completed.returncode
    result["stdout_first_line"] = first_line(completed.stdout)
    result["stderr_first_line"] = first_line(completed.stderr)
    return result


def first_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:240]
    return ""


def validate_policy(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if config.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if config.get("preferred_runtime_binding") != "gpgme":
        errors.append("preferred_runtime_binding must be gpgme")

    for key, message in EXPECTED_TRUE_POLICY.items():
        if config.get(key) is not True:
            errors.append(message)
    for key, message in EXPECTED_FALSE_POLICY.items():
        if config.get(key) is not False:
            errors.append(message)

    probes = config.get("allowed_metadata_probes")
    if not isinstance(probes, list) or not probes:
        errors.append("allowed_metadata_probes must be a non-empty list")
    else:
        seen: set[str] = set()
        for probe in probes:
            if not isinstance(probe, str) or not probe.strip():
                errors.append("allowed_metadata_probes entries must be non-empty strings")
                continue
            if probe in seen:
                errors.append(f"duplicate allowed metadata probe: {probe}")
            seen.add(probe)
            if probe not in ALLOWED_METADATA_PROBES:
                errors.append(f"unapproved metadata probe: {probe}")
            lowered = probe.lower()
            for token in FORBIDDEN_PROBE_TOKENS:
                if token in lowered:
                    errors.append(f"forbidden crypto probe token in allowed metadata probes: {token}")

    requirement = config.get("future_helper_requirement")
    if not isinstance(requirement, str) or "GPGME" not in requirement or "validated account fingerprints" not in requirement:
        errors.append("future_helper_requirement must mention GPGME and validated account fingerprints")

    return errors, warnings


def probe_environment() -> dict[str, Any]:
    probes = {
        "gpg_version": run_metadata_probe(["gpg", "--version"]),
        "gpgme_config_version": run_metadata_probe(["gpgme-config", "--version"]),
        "pkg_config_gpgme_modversion": run_metadata_probe(["pkg-config", "--modversion", "gpgme"]),
        "pkg_config_gpgme_cflags_libs": run_metadata_probe(["pkg-config", "--cflags", "--libs", "gpgme"]),
    }
    gpgme_config_ok = probes["gpgme_config_version"].get("exit_status") == 0
    pkg_config_ok = probes["pkg_config_gpgme_modversion"].get("exit_status") == 0
    gpgme_metadata_detected = bool(gpgme_config_ok or pkg_config_ok)
    return {
        "probes": probes,
        "gpg_available": probes["gpg_version"].get("exit_status") == 0,
        "gpgme_metadata_detected": gpgme_metadata_detected,
        "gpgme_config_available": gpgme_config_ok,
        "pkg_config_gpgme_available": pkg_config_ok,
    }


def build_report(config_path: Path) -> dict[str, Any]:
    config = load_json(config_path)
    errors, warnings = validate_policy(config)
    env = probe_environment()

    if env["gpgme_metadata_detected"]:
        readiness_status = "ready_for_gpgme_design_only"
        next_required_action = "Proceed only to a compile/link scaffold. Runtime cryptographic operations remain disabled until separately implemented and tested."
    else:
        readiness_status = "blocked_missing_gpgme"
        next_required_action = "Install or expose GPGME development metadata before any cryptographic helper implementation. Do not fall back to direct gpg runtime crypto."

    report = {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": utc_now(),
        "config_path": str(config_path),
        "purpose": "Validate V12 OpenPGP GPGME readiness before cryptographic helper integration.",
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "readiness_status": readiness_status,
        "next_required_action": next_required_action,
        "environment": env,
        "safety_invariants": {
            "preferred_runtime_binding_is_gpgme": config.get("preferred_runtime_binding") == "gpgme",
            "gpg_version_metadata_only": True,
            "gpgme_metadata_probe_only": True,
            "direct_gpg_runtime_crypto_allowed": False,
            "fallback_to_direct_gpg_crypto_allowed": False,
            "runtime_crypto_enabled": False,
            "message_decryption_attempted": False,
            "message_signature_verification_attempted": False,
            "message_signing_attempted": False,
            "message_encryption_attempted": False,
            "pgp_mime_parsing_attempted": False,
            "secret_key_listing_attempted": False,
            "secret_key_access_attempted": False,
            "passphrases_prompted_or_stored": False,
            "browser_request_handler_touched_keys": False,
        },
    }
    return report


def write_report(report: dict[str, Any], output: Path | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def run_self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="osmap-v12-gpgme-readiness-test-") as tmp_s:
        tmp = Path(tmp_s)
        good = {
            "schema": SCHEMA,
            "preferred_runtime_binding": "gpgme",
            "require_gpgme_for_crypto_operations": True,
            "allow_direct_gpg_runtime_for_crypto_operations": False,
            "allow_crypto_operations_in_slice5": False,
            "allow_secret_key_listing_in_slice5": False,
            "allow_passphrase_prompting_in_slice5": False,
            "allow_browser_handler_key_access_in_slice5": False,
            "allowed_metadata_probes": sorted(ALLOWED_METADATA_PROBES),
            "future_helper_requirement": "Later helper implementation must use GPGME behind validated account fingerprints.",
        }
        errors, _ = validate_policy(good)
        if errors:
            raise SystemExit(f"valid policy rejected: {errors}")

        bad_cases = []
        for key in EXPECTED_FALSE_POLICY:
            bad = dict(good)
            bad[key] = True
            bad_cases.append((key, bad))
        bad = dict(good)
        bad["preferred_runtime_binding"] = "gpg-command"
        bad_cases.append(("wrong runtime", bad))
        bad = dict(good)
        bad["allowed_metadata_probes"] = ["gpg --decrypt"]
        bad_cases.append(("forbidden decrypt probe", bad))
        bad = dict(good)
        bad["require_gpgme_for_crypto_operations"] = False
        bad_cases.append(("missing gpgme requirement", bad))

        for name, bad in bad_cases:
            errors, _ = validate_policy(bad)
            if not errors:
                raise SystemExit(f"invalid policy accepted: {name}")

        report_path = tmp / "report.json"
        config_path = tmp / "policy.json"
        config_path.write_text(json.dumps(good), encoding="utf-8")
        report = build_report(config_path)
        write_report(report, report_path)
        round_trip = json.loads(report_path.read_text(encoding="utf-8"))
        if not round_trip.get("valid"):
            raise SystemExit("self-test report unexpectedly invalid")
        invariants = round_trip.get("safety_invariants", {})
        for key in [
            "direct_gpg_runtime_crypto_allowed",
            "runtime_crypto_enabled",
            "message_decryption_attempted",
            "message_signature_verification_attempted",
            "message_signing_attempted",
            "message_encryption_attempted",
            "secret_key_listing_attempted",
            "secret_key_access_attempted",
            "passphrases_prompted_or_stored",
            "browser_request_handler_touched_keys",
        ]:
            if invariants.get(key) is not False:
                raise SystemExit(f"unexpected invariant value for {key}")
    print("V12 OpenPGP GPGME readiness self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate V12 OpenPGP GPGME readiness policy")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    report = build_report(args.config)
    write_report(report, args.output)
    if not report.get("valid"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
