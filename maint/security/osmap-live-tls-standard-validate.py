#!/usr/bin/env python3
"""Validate the live OSMAP HTTPS edge against the project TLS standard."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any


DEFAULT_TARGET = "https://mail.blackbagsecurity.com"
WEAK_CIPHER_MARKERS = ("ANON", "NULL", "EXPORT", "MD5", "RC4", "3DES", "DES", "CBC")


def osmap_tls_client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def parse_target(value: str) -> tuple[str, int, str]:
    parsed = urllib.parse.urlparse(value if "://" in value else f"https://{value}")
    scheme = parsed.scheme or "https"
    if scheme != "https":
        raise ValueError("TLS validation target must use https")
    host = parsed.hostname
    if not host:
        raise ValueError("TLS validation target is missing a hostname")
    return host, parsed.port or 443, scheme


def parse_protocol(output: str) -> str:
    patterns = [
        r"Protocol\s*:\s*(TLSv[0-9.]+)",
        r"New,\s*(TLSv[0-9.]+),\s*Cipher is",
        r"Protocol version:\s*(TLSv[0-9.]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output)
        if match:
            return match.group(1)
    return ""


def parse_cipher(output: str) -> str:
    patterns = [
        r"Cipher\s*:\s*([A-Za-z0-9_-]+)",
        r"Cipher is\s*([A-Za-z0-9_-]+)",
        r"Ciphersuite:\s*([A-Za-z0-9_-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output)
        if match:
            cipher = match.group(1)
            return "" if cipher in {"0000", "NONE"} else cipher
    return ""


def verify_ok(output: str) -> bool:
    return "Verify return code: 0 (ok)" in output or "Verification: OK" in output


def weak_cipher_reason(cipher: str) -> str:
    upper = cipher.upper()
    for marker in WEAK_CIPHER_MARKERS:
        if marker in upper:
            return f"cipher contains prohibited marker {marker}"
    if upper in {"AES256-SHA", "AES128-SHA"}:
        return "cipher is a legacy non-AEAD SHA suite"
    return ""


def tls12_cipher_is_strong(cipher: str) -> tuple[bool, str]:
    weak = weak_cipher_reason(cipher)
    if weak:
        return False, weak
    upper = cipher.upper()
    if not (upper.startswith("ECDHE-") or upper.startswith("DHE-")):
        return False, "TLS 1.2 cipher is not forward-secret"
    if not any(token in upper for token in ("GCM", "CHACHA20-POLY1305", "CCM")):
        return False, "TLS 1.2 cipher is not AEAD"
    return True, ""


def tls13_cipher_is_strong(cipher: str) -> tuple[bool, str]:
    weak = weak_cipher_reason(cipher)
    if weak:
        return False, weak
    upper = cipher.upper()
    if not upper.startswith("TLS_"):
        return False, "TLS 1.3 cipher name is unexpected"
    if not any(token in upper for token in ("GCM", "CHACHA20_POLY1305", "CCM")):
        return False, "TLS 1.3 cipher is not in the expected AEAD family"
    return True, ""


def python_verified_probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    context = osmap_tls_client_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cipher_info = tls_sock.cipher()
            return {
                "status": "passed",
                "protocol": tls_sock.version() or "",
                "cipher": cipher_info[0] if cipher_info else "",
                "certificate_validation": context.verify_mode == ssl.CERT_REQUIRED,
                "hostname_validation": context.check_hostname is True,
                "minimum_version": context.minimum_version.name,
            }


def openssl_probe(
    openssl_bin: str,
    host: str,
    port: int,
    timeout: float,
    version_flag: str,
    *,
    cipher: str | None = None,
    verify_hostname_supported: bool = True,
) -> dict[str, Any]:
    command = [
        openssl_bin,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-verify_return_error",
    ]
    if verify_hostname_supported:
        command.extend(["-verify_hostname", host])
    command.append(version_flag)
    if cipher:
        command.extend(["-cipher", cipher])
    try:
        completed = subprocess.run(
            command,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        return {
            "command": " ".join(command),
            "returncode": completed.returncode,
            "protocol": parse_protocol(output),
            "cipher": parse_cipher(output),
            "verify_ok": verify_ok(output),
            "output_excerpt": "\n".join(output.splitlines()[:20]),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": " ".join(command),
            "returncode": 124 if isinstance(exc, subprocess.TimeoutExpired) else 127,
            "protocol": "",
            "cipher": "",
            "verify_ok": False,
            "output_excerpt": str(exc),
        }


def openssl_s_client_supports_option(openssl_bin: str, option: str) -> bool:
    try:
        completed = subprocess.run(
            [openssl_bin, "s_client", "-help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = completed.stdout.decode("utf-8", errors="replace")
    return option in output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default=None, help="HTTPS URL or host to validate")
    parser.add_argument("--report", default=None, help="write JSON evidence to this path")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--openssl-bin", default="openssl")
    args = parser.parse_args()

    target = args.target or DEFAULT_TARGET
    host, port, _scheme = parse_target(target)
    report_path = Path(args.report) if args.report else None
    failures: list[str] = []
    probes: dict[str, Any] = {}
    verify_hostname_supported = openssl_s_client_supports_option(args.openssl_bin, "-verify_hostname")

    try:
        probes["python_default_context"] = python_verified_probe(host, port, args.timeout)
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        probes["python_default_context"] = {"status": "failed", "error": str(exc)}
        failures.append(f"verified Python TLS client probe failed: {exc}")

    for label, flag in (("tls10", "-tls1"), ("tls11", "-tls1_1")):
        probe = openssl_probe(
            args.openssl_bin,
            host,
            port,
            args.timeout,
            flag,
            verify_hostname_supported=verify_hostname_supported,
        )
        negotiated = bool(probe.get("protocol") and probe.get("cipher"))
        if negotiated:
            probe["status"] = "failed"
            failures.append(f"{label} unexpectedly negotiated {probe.get('protocol')} {probe.get('cipher')}")
        else:
            probe["status"] = "rejected"
            probe["protocol"] = ""
            probe["cipher"] = ""
            probe["verify_ok"] = False
        probes[label] = probe

    tls12 = openssl_probe(
        args.openssl_bin,
        host,
        port,
        args.timeout,
        "-tls1_2",
        verify_hostname_supported=verify_hostname_supported,
    )
    tls12_ok, tls12_reason = tls12_cipher_is_strong(str(tls12.get("cipher", "")))
    tls12["strong_cipher"] = tls12_ok
    if tls12.get("protocol") != "TLSv1.2" or not tls12.get("cipher") or not tls12.get("verify_ok") or not tls12_ok:
        tls12["status"] = "failed"
        failures.append(
            "TLS 1.2 probe failed standard "
            f"(protocol={tls12.get('protocol')!r}, cipher={tls12.get('cipher')!r}, verify_ok={tls12.get('verify_ok')!r}, reason={tls12_reason!r})"
        )
    else:
        tls12["status"] = "passed"
    if tls12_reason:
        tls12["cipher_reason"] = tls12_reason
    probes["tls12"] = tls12

    tls13 = openssl_probe(
        args.openssl_bin,
        host,
        port,
        args.timeout,
        "-tls1_3",
        verify_hostname_supported=verify_hostname_supported,
    )
    tls13_ok, tls13_reason = tls13_cipher_is_strong(str(tls13.get("cipher", "")))
    tls13["strong_cipher"] = tls13_ok
    if tls13.get("protocol") != "TLSv1.3" or not tls13.get("cipher") or not tls13.get("verify_ok") or not tls13_ok:
        tls13["status"] = "failed"
        failures.append(
            "TLS 1.3 probe failed standard "
            f"(protocol={tls13.get('protocol')!r}, cipher={tls13.get('cipher')!r}, verify_ok={tls13.get('verify_ok')!r}, reason={tls13_reason!r})"
        )
    else:
        tls13["status"] = "passed"
    if tls13_reason:
        tls13["cipher_reason"] = tls13_reason
    probes["tls13"] = tls13

    report: dict[str, Any] = {
        "result": "tls_standard_passed" if not failures else "tls_standard_failed",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "target": f"https://{host}:{port}",
        "host": host,
        "port": port,
        "minimum_tls_version": "TLSv1.2",
        "preferred_tls_version": "TLSv1.3",
        "certificate_validation": probes.get("python_default_context", {}).get("certificate_validation") is True,
        "hostname_validation": probes.get("python_default_context", {}).get("hostname_validation") is True,
        "openssl_verify_hostname_supported": verify_hostname_supported,
        "probes": probes,
        "failures": failures,
    }

    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
