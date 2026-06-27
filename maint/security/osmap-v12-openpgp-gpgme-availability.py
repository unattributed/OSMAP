#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIG_SCHEMA = "osmap-v12-openpgp-gpgme-availability-v1"
REPORT_SCHEMA = "osmap-v12-openpgp-gpgme-availability-report-v1"
EXPECTED_FALSE = [
    "runtime_crypto_enabled",
    "direct_gpg_runtime_crypto_allowed",
    "fallback_to_direct_gpg_crypto_allowed",
    "message_decryption_attempted",
    "message_signature_verification_attempted",
    "message_signing_attempted",
    "message_encryption_attempted",
    "pgp_mime_parsing_attempted",
    "passphrases_prompted_or_stored",
    "secret_key_access_attempted",
    "secret_key_listing_attempted",
    "browser_request_handler_touched_keys",
]
EXPECTED_TRUE = [
    "preferred_runtime_binding_is_gpgme",
    "gpgme_metadata_probe_only",
    "gpg_version_metadata_only",
]
FORBIDDEN_CONFIG_FIELDS = {
    "decrypt",
    "encrypt",
    "sign",
    "verify",
    "pgp_mime_parse",
    "passphrase",
    "secret_key",
    "private_key",
    "list_secret_keys",
    "raw_message_body",
    "decrypted_plaintext",
    "trusted_html",
    "direct_gpg_crypto",
    "gpg_crypto_fallback",
}

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def first_line(value: str) -> str:
    for line in value.splitlines():
        clean = line.strip()
        if clean:
            return clean[:240]
    return ""

def run_probe(argv: list[str]) -> dict[str, Any]:
    found = shutil.which(argv[0]) is not None
    if not found:
        return {"argv": argv, "executable_found": False, "exit_status": None, "stdout_first_line": "", "stderr_first_line": ""}
    completed = subprocess.run(argv, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return {"argv": argv, "executable_found": True, "exit_status": completed.returncode, "stdout_first_line": first_line(completed.stdout), "stderr_first_line": first_line(completed.stderr)}

def compile_probe(flags: str) -> dict[str, Any]:
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if cc is None:
        return {"attempted": False, "available": False, "exit_status": None, "stdout_first_line": "", "stderr_first_line": "compiler not found"}
    source = "#include <gpgme.h>\nint main(void) { const char *v = GPGME_VERSION; return v == 0; }\n"
    with tempfile.TemporaryDirectory(prefix="osmap-gpgme-compile-") as tmp:
        src = Path(tmp) / "probe.c"
        out = Path(tmp) / "probe"
        src.write_text(source, encoding="utf-8")
        completed = subprocess.run([cc, str(src), "-o", str(out)] + flags.split(), check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return {"attempted": True, "available": completed.returncode == 0, "exit_status": completed.returncode, "stdout_first_line": first_line(completed.stdout), "stderr_first_line": first_line(completed.stderr)}

def keys(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from keys(item)

def validate_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("schema") != CONFIG_SCHEMA:
        errors.append("unexpected schema")
    all_keys = set(keys(config))
    for field in sorted(FORBIDDEN_CONFIG_FIELDS):
        if field in all_keys:
            errors.append(f"forbidden runtime field present: {field}")
    dep = config.get("dependency_policy")
    if not isinstance(dep, dict):
        errors.append("dependency_policy object is required")
    else:
        expected = {
            "preferred_runtime_binding": "gpgme",
            "require_pkg_config_metadata": True,
            "require_no_direct_gpg_crypto_fallback": True,
            "direct_gpg_runtime_crypto_allowed": False,
            "runtime_crypto_enabled": False,
            "metadata_probe_only": True,
            "compile_or_link_probe_crypto_allowed": False,
        }
        for key, value in expected.items():
            if dep.get(key) != value:
                errors.append(f"dependency_policy.{key} must be {value!r}")
    remediation = config.get("remediation_policy")
    if not isinstance(remediation, dict):
        errors.append("remediation_policy object is required")
    else:
        if remediation.get("install_is_operator_controlled") is not True:
            errors.append("remediation_policy.install_is_operator_controlled must be true")
        if "libgpgme-dev" not in remediation.get("debian_packages", []) or "pkg-config" not in remediation.get("debian_packages", []):
            errors.append("debian package list must include pkg-config and libgpgme-dev")
        if "gpgme" not in remediation.get("openbsd_packages", []) or "pkgconf" not in remediation.get("openbsd_packages", []):
            errors.append("OpenBSD package list must include pkgconf and gpgme")
    inv = config.get("safety_invariants")
    if not isinstance(inv, dict):
        errors.append("safety_invariants object is required")
    else:
        for key in EXPECTED_TRUE:
            if inv.get(key) is not True:
                errors.append(f"safety_invariants.{key} must be true")
        for key in EXPECTED_FALSE:
            if inv.get(key) is not False:
                errors.append(f"safety_invariants.{key} must be false")
    return errors

def live_environment() -> dict[str, Any]:
    probes = {
        "gpg_version": run_probe(["gpg", "--version"]),
        "gpgme_config_version": run_probe(["gpgme-config", "--version"]),
        "pkg_config_gpgme_modversion": run_probe(["pkg-config", "--modversion", "gpgme"]),
        "pkg_config_gpgme_cflags_libs": run_probe(["pkg-config", "--cflags", "--libs", "gpgme"]),
    }
    pkg_ok = probes["pkg_config_gpgme_modversion"].get("exit_status") == 0
    flags = ""
    if probes["pkg_config_gpgme_cflags_libs"].get("exit_status") == 0:
        full = subprocess.run(["pkg-config", "--cflags", "--libs", "gpgme"], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if full.returncode == 0:
            flags = full.stdout.strip()
    compiled = compile_probe(flags) if pkg_ok else {"attempted": False, "available": False, "exit_status": None, "stdout_first_line": "", "stderr_first_line": "pkg-config gpgme unavailable"}
    return {
        "gpg_available": probes["gpg_version"].get("exit_status") == 0,
        "gpgme_config_available": probes["gpgme_config_version"].get("exit_status") == 0,
        "pkg_config_available": probes["pkg_config_gpgme_modversion"].get("executable_found") is True,
        "pkg_config_gpgme_available": pkg_ok,
        "gpgme_metadata_detected": pkg_ok or probes["gpgme_config_version"].get("exit_status") == 0,
        "compile_or_link_probe": compiled,
        "probes": probes,
    }

def fake_environment(available: bool) -> dict[str, Any]:
    return {"gpg_available": True, "gpgme_config_available": available, "pkg_config_available": True, "pkg_config_gpgme_available": available, "gpgme_metadata_detected": available, "compile_or_link_probe": {"attempted": available, "available": available, "exit_status": 0 if available else None, "stdout_first_line": "", "stderr_first_line": ""}, "probes": {}}

def build_report(config_path: Path, config: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    errors = validate_config(config)
    compile_result = env.get("compile_or_link_probe", {})
    pkg_ok = env.get("pkg_config_gpgme_available") is True
    compile_ok = compile_result.get("available") is True or compile_result.get("attempted") is False
    if compile_result.get("attempted") is True and compile_result.get("available") is not True:
        errors.append("GPGME compile or link probe failed")
    available = pkg_ok and compile_ok
    warnings = [] if available else ["GPGME pkg-config metadata is missing or compile/link proof failed; future OpenPGP crypto remains blocked."]
    status = "available" if available else "blocked_missing_gpgme"
    return {"schema": REPORT_SCHEMA, "purpose": "Prove V12 OpenPGP GPGME availability before cryptographic helper integration.", "config_path": str(config_path), "generated_at_utc": utc_now(), "availability_status": status, "valid": len(errors) == 0, "errors": errors, "warnings": warnings, "environment": env, "safety_invariants": dict(sorted(config.get("safety_invariants", {}).items())), "next_required_action": "Proceed to a GPGME compile-only helper scaffold in a later slice; runtime crypto remains disabled." if status == "available" else "Install or expose GPGME development metadata. Do not fall back to direct gpg runtime crypto."}

def write_report(report: dict[str, Any], path: Path | None, emit: bool) -> None:
    data = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
    if emit:
        sys.stdout.write(data)

def good_config() -> dict[str, Any]:
    return {"schema": CONFIG_SCHEMA, "purpose": "self test", "dependency_policy": {"preferred_runtime_binding": "gpgme", "require_pkg_config_metadata": True, "require_no_direct_gpg_crypto_fallback": True, "direct_gpg_runtime_crypto_allowed": False, "runtime_crypto_enabled": False, "metadata_probe_only": True, "compile_or_link_probe_crypto_allowed": False}, "remediation_policy": {"install_is_operator_controlled": True, "debian_packages": ["pkg-config", "libgpgme-dev"], "openbsd_packages": ["pkgconf", "gpgme"]}, "safety_invariants": {**{key: True for key in EXPECTED_TRUE}, **{key: False for key in EXPECTED_FALSE}}}

def self_test() -> None:
    good = good_config()
    report = build_report(Path("self-test-good.json"), good, fake_environment(True))
    if not report["valid"] or report["availability_status"] != "available":
        raise AssertionError("good self-test did not validate")
    blocked = build_report(Path("self-test-blocked.json"), good, fake_environment(False))
    if not blocked["valid"] or blocked["availability_status"] != "blocked_missing_gpgme":
        raise AssertionError("blocked metadata state should remain valid without require-available")
    bad = json.loads(json.dumps(good))
    bad["dependency_policy"]["direct_gpg_runtime_crypto_allowed"] = True
    if build_report(Path("bad.json"), bad, fake_environment(True))["valid"]:
        raise AssertionError("bad direct gpg fallback unexpectedly validated")
    print("V12 OpenPGP GPGME availability self-test passed")

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--emit", action="store_true")
    parser.add_argument("--require-available", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.config is None:
        parser.error("--config is required unless --self-test is used")
    report = build_report(args.config, json.loads(args.config.read_text(encoding="utf-8")), live_environment())
    write_report(report, args.report, args.emit)
    if args.require_available and report.get("availability_status") != "available":
        return 2
    return 0 if report.get("valid") else 1

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
