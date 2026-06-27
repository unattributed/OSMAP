#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "osmap-v12-openpgp-diagnostics-v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def command_text(argv: list[str]) -> dict[str, Any]:
    exe = shutil.which(argv[0])
    if not exe:
        return {"available": False, "argv0": argv[0], "status": "missing"}
    try:
        result = subprocess.run(
            [exe, *argv[1:]],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except Exception as exc:
        return {"available": True, "argv0": argv[0], "status": "error", "error": type(exc).__name__}
    return {
        "available": True,
        "argv0": argv[0],
        "status": "ok" if result.returncode == 0 else "nonzero",
        "returncode": result.returncode,
        "stdout_first_line": (result.stdout.splitlines() or [""])[0],
    }


def collect_public_key_colons() -> str:
    gpg = shutil.which("gpg")
    if not gpg:
        return ""
    result = subprocess.run(
        [
            gpg,
            "--batch",
            "--with-colons",
            "--fixed-list-mode",
            "--keyid-format",
            "LONG",
            "--list-keys",
            "--fingerprint",
            "--fingerprint",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if result.returncode not in (0, 2):
        return ""
    return result.stdout


def parse_public_keys(colons: str) -> list[dict[str, Any]]:
    keys: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def finish() -> None:
        nonlocal current
        if current is not None:
            if current.get("primary_fingerprint"):
                keys.append(current)
            current = None

    for raw_line in colons.splitlines():
        fields = raw_line.split(":")
        record_type = fields[0] if fields else ""
        if record_type == "pub":
            finish()
            current = {
                "record_type": "public_primary_key",
                "validity": fields[1] if len(fields) > 1 else "",
                "key_length": fields[2] if len(fields) > 2 else "",
                "public_key_algorithm": fields[3] if len(fields) > 3 else "",
                "key_id": fields[4] if len(fields) > 4 else "",
                "created_epoch": fields[5] if len(fields) > 5 else "",
                "expires_epoch": fields[6] if len(fields) > 6 else "",
                "ownertrust": fields[8] if len(fields) > 8 else "",
                "capabilities": fields[11] if len(fields) > 11 else "",
                "primary_fingerprint": "",
                "uid_count": 0,
                "subkey_count": 0,
            }
        elif record_type == "fpr" and current is not None and not current.get("primary_fingerprint"):
            current["primary_fingerprint"] = fields[9] if len(fields) > 9 else ""
        elif record_type == "uid" and current is not None:
            current["uid_count"] = int(current["uid_count"]) + 1
        elif record_type == "sub" and current is not None:
            current["subkey_count"] = int(current["subkey_count"]) + 1
    finish()
    return keys


def collect_toolchain() -> dict[str, Any]:
    return {
        "gpg": command_text(["gpg", "--version"]),
        "gpgme_config": command_text(["gpgme-config", "--version"]),
        "pkg_config_gpgme": command_text(["pkg-config", "--modversion", "gpgme"]),
    }


def build_report() -> dict[str, Any]:
    colons = collect_public_key_colons()
    public_keys = parse_public_keys(colons)
    return {
        "schema": SCHEMA,
        "generated_at_utc": utc_now(),
        "purpose": "OpenPGP public key inventory and toolchain diagnostics only.",
        "safety_invariants": {
            "private_key_material_collected": False,
            "secret_key_inventory_collected": False,
            "uid_values_collected": False,
            "passphrases_prompted_or_stored": False,
            "message_decryption_attempted": False,
            "message_signing_attempted": False,
            "message_encryption_attempted": False,
            "browser_request_handler_touched_keys": False,
        },
        "toolchain": collect_toolchain(),
        "public_key_inventory": {
            "key_count": len(public_keys),
            "keys": public_keys,
            "uid_values_omitted": True,
            "fingerprints_recorded": True,
        },
        "next_required_boundary": "Account capability binding must use explicit configured fingerprints and must fail closed on ambiguous matches.",
    }


def write_outputs(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "openpgp-diagnostics.json"
    md_path = output_dir / "openpgp-diagnostics-summary.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    inv = report["public_key_inventory"]
    lines = [
        "# OSMAP V12 OpenPGP Diagnostics Summary",
        "",
        f"Schema: `{report['schema']}`",
        f"Generated UTC: `{report['generated_at_utc']}`",
        "",
        "## Safety",
        "",
        "This diagnostic collects public key fingerprints and capability metadata only.",
        "It does not collect user ID values, secret key records, private key material, passphrases, decrypted plaintext, or signed content.",
        "",
        "## Toolchain",
        "",
    ]
    for name, data in report["toolchain"].items():
        lines.append(f"- `{name}`: `{data.get('status')}`")
    lines.extend([
        "",
        "## Public key inventory",
        "",
        f"- Public primary keys observed: `{inv['key_count']}`",
        "- User ID values collected: `false`",
        "",
    ])
    for key in inv["keys"]:
        lines.append(f"- fingerprint `{key['primary_fingerprint']}` capabilities `{key.get('capabilities', '')}` uid_count `{key.get('uid_count', 0)}` subkey_count `{key.get('subkey_count', 0)}`")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> int:
    fixture = """pub:u:4096:1:AAAABBBBCCCCDDDD:1741600000:2057136000::u:::scESC::::::23::0:\nfpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\nuid:u::::1741600000::x::Alice Example <alice@example.test>::::::::::0:\nsub:u:4096:1:1111222233334444:1741600000:2057136000:::::e::::::23:\nfpr:::::::::89ABCDEF0123456789ABCDEF0123456789ABCDEF:\n"""
    parsed = parse_public_keys(fixture)
    assert len(parsed) == 1, parsed
    assert parsed[0]["primary_fingerprint"] == "0123456789ABCDEF0123456789ABCDEF01234567"
    assert parsed[0]["uid_count"] == 1
    assert parsed[0]["subkey_count"] == 1
    encoded = json.dumps({"keys": parsed})
    assert "alice@example" not in encoded
    report = build_report()
    assert report["safety_invariants"]["private_key_material_collected"] is False
    assert report["safety_invariants"]["uid_values_collected"] is False
    assert report["schema"] == SCHEMA
    print("V12 OpenPGP diagnostics self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="OSMAP V12 OpenPGP diagnostics")
    parser.add_argument("--output", type=Path, help="directory for sanitized diagnostics output")
    parser.add_argument("--self-test", action="store_true", help="run parser and invariant self-tests")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.output:
        parser.error("--output is required unless --self-test is used")
    report = build_report()
    write_outputs(report, args.output)
    print(f"wrote OpenPGP diagnostics to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
