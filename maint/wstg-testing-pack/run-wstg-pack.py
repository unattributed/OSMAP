#!/usr/bin/env python3
"""Evidence-producing OWASP WSTG v4.2 runner for the OSMAP browser surface."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import html
import hmac
import http.client
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARNING = "warning"
STATUS_SKIP = "skip"
STATUS_NA = "not_applicable"

PACK_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACK_ROOT.parents[1]
MAPPING_PATH = PACK_ROOT / "wstg-asvs-mapping.json"
DEFAULT_WSTG_MATRIX_FILE = "wstg-scenario-matrix.v42.json"
ALLOWED_MATRIX_DISPOSITIONS = {
    "automated",
    "manual",
    "not_applicable",
    "covered_by_other_evidence",
    "deferred",
    "blocked",
}

OWASP_TOP_10_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}
DEFAULT_BODY_LIMIT = 256 * 1024
SECRET_REPLACEMENT = "[REDACTED]"
REFLECTED_INPUT_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "' autofocus onfocus=alert(1) x='",
    "javascript:alert(1)",
]
PATH_TRAVERSAL_PROBES = {
    "path_traversal_dotdot": "/mailboxes/../login",
    "path_traversal_encoded": "/mailboxes/%2e%2e/login",
    "path_traversal_double_encoded": "/attachment?mailbox=%252e%252e%252f%252e%252e%252fetc&uid=1&part=1",
    "path_traversal_attachment": "/attachment?mailbox=..%2f..%2fetc&uid=1&part=1",
    "path_traversal_absolute": "/attachment?mailbox=%2fetc%2fpasswd&uid=1&part=1",
}
COMMAND_INJECTION_SLEEP_SECONDS = 2
COMMAND_INJECTION_DIAGNOSTIC_PATTERNS = [
    r"(?i)\b(?:sh|ksh|bash|dash|zsh): .*?(?:not found|syntax error|bad substitution|unexpected|unterminated|permission denied|cannot)",
    r"(?i)\b(?:execve|posix_spawn|pledge|unveil)\b.*?(?:failed|denied|not permitted|permission denied)",
    r"(?i)\bcommand not found\b",
]
COMMAND_INJECTION_PANIC_PATTERNS = [
    r"(?i)\bpanic(?:ked)?\b",
    r"(?i)stack backtrace",
    r"(?i)rust_backtrace",
    r"(?i)thread '.*' panicked",
    r"(?i)traceback \(most recent call last\)",
]


def osmap_tls_client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def parse_raw_http_evidence(
    label: str,
    response: bytes,
    *,
    error: str = "",
    truncated: bool = False,
) -> HttpEvidence:
    if not response:
        return HttpEvidence(label, None, "", [], b"", truncated=truncated, error=error)
    header_bytes, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        header_bytes, separator, body = response.partition(b"\n\n")
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = header_text.replace("\r\n", "\n").split("\n")
    status = None
    reason = ""
    headers: list[tuple[str, str]] = []
    if lines:
        match = re.match(r"^HTTP/\S+\s+(\d{3})(?:\s+(.*))?$", lines[0])
        if match:
            status = int(match.group(1))
            reason = match.group(2) or ""
            for line in lines[1:]:
                if not line or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                headers.append((key.strip(), value.strip()))
        else:
            error = error or "raw response did not start with an HTTP status line"
            body = response
    return HttpEvidence(label, status, reason, headers, body, truncated=truncated, error=error)


@dataclass
class Config:
    base_url: str
    host: str
    ssh_host: str
    test_email: str
    test_password: str
    totp_secret: str
    secondary_email: str
    output_dir: Path
    rate_delay: float
    allow_authenticated: bool
    prompt_auth: bool
    allow_host_assisted: bool
    throttle_attempts: int
    timeout: float
    ssh_timeout: float
    release_mode: bool
    wstg_source_name: str
    wstg_source_url: str
    wstg_source_version: str
    wstg_source_commit: str
    wstg_matrix_file: str

    @property
    def parsed_base(self) -> urllib.parse.ParseResult:
        return urllib.parse.urlparse(self.base_url)

    @property
    def scheme(self) -> str:
        return self.parsed_base.scheme or "https"

    @property
    def port(self) -> int:
        if self.parsed_base.port:
            return self.parsed_base.port
        return 443 if self.scheme == "https" else 80


@dataclass
class HttpEvidence:
    label: str
    status: int | None
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool = False
    error: str = ""

    def header_values(self, name: str) -> list[str]:
        needle = name.lower()
        return [value for key, value in self.headers if key.lower() == needle]

    def first_header(self, name: str) -> str:
        values = self.header_values(name)
        return values[0] if values else ""

    def body_text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class TestResult:
    test_id: str
    test_name: str
    status: str
    message: str
    evidence: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


class Runner:
    def __init__(self, config: Config, mapping: dict[str, object], run_dir: Path) -> None:
        self.config = config
        self.mapping = mapping
        self.run_dir = run_dir
        self.evidence_dir = run_dir / "evidence"
        self.log_dir = run_dir / "logs"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[TestResult] = []
        self.cookie_jar: dict[str, str] = {}
        self.authenticated = False
        self.csrf_token = ""
        self.prompted_password = ""
        self.last_login_set_cookie_headers: list[str] = []
        self.mime_html_live_report: str | None = None
        self.authenticated_proof: dict[str, bool] = {
            "login": False,
            "totp": False,
            "session_issued": False,
            "protected_route_access": False,
            "logout": False,
            "session_invalidated": False,
        }
        self.secrets = [
            value
            for value in (
                config.test_email,
                config.test_password,
                config.totp_secret,
                config.secondary_email,
            )
            if value
        ]

    def run(self, selected_ids: set[str] | None = None) -> list[TestResult]:
        tests: dict[str, Callable[[], TestResult]] = {
            "OSMAP-WSTG-CONF-001": self.test_tls_and_redirect,
            "OSMAP-WSTG-CONF-002": self.test_security_headers,
            "OSMAP-WSTG-CONF-003": self.test_csp,
            "OSMAP-WSTG-CONF-008": self.test_sensitive_extension_and_backup_exposure,
            "OSMAP-WSTG-CONF-009": self.test_ria_cloud_storage_applicability,
            "OSMAP-WSTG-CONF-010": self.test_file_permissions_and_subdomain_takeover,
            "OSMAP-WSTG-ATHN-001": self.test_login_form,
            "OSMAP-WSTG-ATHN-002": self.test_invalid_login,
            "OSMAP-WSTG-ATHN-003": self.test_throttle_probe,
            "OSMAP-WSTG-ATHN-004": self.test_authenticated_login,
            "OSMAP-WSTG-SESS-001": self.test_session_cookie_flags,
            "OSMAP-WSTG-SESS-002": self.test_session_fixation,
            "OSMAP-WSTG-SESS-003": self.test_logout_csrf,
            "OSMAP-WSTG-SESS-004": self.test_authenticated_csrf,
            "OSMAP-WSTG-SESS-005": self.test_authenticated_cache_control,
            "OSMAP-WSTG-SESS-006": self.test_session_lifecycle_policy,
            "OSMAP-WSTG-CONF-004": self.test_methods,
            "OSMAP-WSTG-INFO-001": self.test_metafiles,
            "OSMAP-WSTG-INFO-002": self.test_info_disclosure,
            "OSMAP-WSTG-INFO-003": self.test_error_and_route_inventory,
            "OSMAP-WSTG-INFO-004": self.test_public_reconnaissance_fingerprinting,
            "OSMAP-WSTG-INPV-001": self.test_path_traversal,
            "OSMAP-WSTG-INPV-002": self.test_reflected_input,
            "OSMAP-WSTG-INPV-003": self.test_command_injection,
            "OSMAP-WSTG-INPV-004": self.test_webmail_input_validation,
            "OSMAP-WSTG-INPV-005": self.test_http_input_tampering,
            "OSMAP-WSTG-INPV-006": self.test_http_host_and_smuggling_input,
            "OSMAP-WSTG-INPV-007": self.test_injection_applicability_static,
            "OSMAP-WSTG-CLNT-001": self.test_cors,
            "OSMAP-WSTG-CLNT-002": self.test_html_rendering_live,
            "OSMAP-WSTG-CLNT-003": self.test_client_side_applicability_static,
            "OSMAP-WSTG-BUSL-001": self.test_attachment_live,
            "OSMAP-WSTG-ATHZ-001": self.test_authorization_account_isolation,
            "OSMAP-WSTG-BUSL-002": self.test_draft_routes_authenticated,
            "OSMAP-WSTG-BUSL-003": self.test_source_attachments_authenticated,
            "OSMAP-WSTG-BUSL-004": self.test_bulk_folder_actions_live,
            "OSMAP-WSTG-BUSL-005": self.test_form_route_state_transitions_static,
            "OSMAP-WSTG-APIT-001": self.test_graphql_applicability_static,
            "OSMAP-WSTG-CONF-005": self.test_host_bindings,
            "OSMAP-WSTG-CONF-006": self.test_host_pf,
            "OSMAP-WSTG-CONF-007": self.test_dependency_alignment,
            "OSMAP-WSTG-CRYP-001": self.test_crypto_transport_security,
            "OSMAP-WSTG-CRYP-002": self.test_crypto_primitive_applicability_static,
            "OSMAP-WSTG-LOGG-001": self.test_security_logging_static,
        }
        for item in self.mapping["tests"]:
            test_id = item["test_id"]
            if selected_ids and test_id not in selected_ids:
                continue
            func = tests[test_id]
            try:
                result = func()
            except Exception as exc:  # noqa: BLE001 - runner must capture every test crash.
                result = self.result(
                    test_id,
                    STATUS_FAIL,
                    f"test raised unexpected error: {exc}",
                    details={"exception_type": type(exc).__name__},
                )
            self.results.append(result)
            print(f"{result.status.upper():15} {result.test_id} {result.message}")
        return self.results

    def mapping_item(self, test_id: str) -> dict[str, object]:
        for item in self.mapping["tests"]:
            if item["test_id"] == test_id:
                return item
        raise KeyError(test_id)

    def result(
        self,
        test_id: str,
        status: str,
        message: str,
        evidence: Iterable[str] = (),
        details: dict[str, object] | None = None,
    ) -> TestResult:
        return TestResult(
            test_id=test_id,
            test_name=str(self.mapping_item(test_id)["test_name"]),
            status=status,
            message=message,
            evidence=list(evidence),
            details=details or {},
        )

    def request(
        self,
        label: str,
        method: str,
        path: str,
        *,
        scheme: str | None = None,
        host: str | None = None,
        port: int | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | str = b"",
        cookies: dict[str, str] | None = None,
        store_cookies: bool = False,
        store_body_evidence: bool = True,
    ) -> HttpEvidence:
        scheme = scheme or self.config.scheme
        host = host or self.config.host
        if port is None:
            port = 443 if scheme == "https" else 80
        headers = dict(headers or {})
        headers.setdefault("Host", host)
        headers.setdefault("User-Agent", "osmap-wstg-pack/1.0")
        if cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        if body_bytes and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body_bytes))
        evidence = HttpEvidence(label, None, "", [], b"")
        try:
            if scheme == "https":
                context = osmap_tls_client_context()
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    host, port=port, timeout=self.config.timeout, context=context
                )
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=self.config.timeout)
            conn.request(method, path, body=body_bytes, headers=headers)
            response = conn.getresponse()
            body_data = response.read(DEFAULT_BODY_LIMIT)
            truncated = bool(response.read(1))
            evidence = HttpEvidence(
                label=label,
                status=response.status,
                reason=response.reason,
                headers=response.getheaders(),
                body=body_data,
                truncated=truncated,
            )
            if store_cookies:
                self.store_response_cookies(evidence)
            conn.close()
        except (OSError, ssl.SSLError, socket.timeout) as exc:
            evidence = HttpEvidence(label, None, "", [], b"", error=str(exc))
        self.write_http_evidence(evidence, store_body=store_body_evidence)
        return evidence

    def raw_http_request(self, label: str, raw_request: bytes) -> HttpEvidence:
        host = self.config.host
        response = b""
        error = ""
        truncated = False
        try:
            sock = socket.create_connection((host, self.config.port), timeout=self.config.timeout)
            if self.config.scheme == "https":
                context = osmap_tls_client_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(self.config.timeout)
            sock.sendall(raw_request)
            while len(response) < DEFAULT_BODY_LIMIT:
                chunk = sock.recv(min(4096, DEFAULT_BODY_LIMIT - len(response)))
                if not chunk:
                    break
                response += chunk
            if len(response) >= DEFAULT_BODY_LIMIT:
                truncated = True
            sock.close()
        except (OSError, ssl.SSLError, socket.timeout) as exc:
            error = str(exc)

        evidence = parse_raw_http_evidence(label, response, error=error, truncated=truncated)
        self.write_http_evidence(evidence)
        return evidence

    def form_post(
        self,
        label: str,
        path: str,
        values: dict[str, str],
        *,
        cookies: dict[str, str] | None = None,
        store_cookies: bool = False,
        headers: dict[str, str] | None = None,
        store_body_evidence: bool = True,
    ) -> HttpEvidence:
        encoded = urllib.parse.urlencode(values)
        merged_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            merged_headers.update(headers)
        return self.request(
            label,
            "POST",
            path,
            headers=merged_headers,
            body=encoded,
            cookies=cookies,
            store_cookies=store_cookies,
            store_body_evidence=store_body_evidence,
        )

    def write_http_evidence(self, evidence: HttpEvidence, *, store_body: bool = True) -> None:
        stem = safe_label(evidence.label)
        headers_path = self.evidence_dir / f"{stem}.headers"
        body_path = self.evidence_dir / f"{stem}.body"
        lines = []
        if evidence.status is None:
            lines.append(f"ERROR: {self.redact(evidence.error)}\n")
        else:
            lines.append(f"HTTP {evidence.status} {evidence.reason}\n")
            lines.append(f"X-OSMAP-WSTG-Body-Truncated: {str(evidence.truncated).lower()}\n")
            for key, value in evidence.headers:
                if key.lower() in {"set-cookie", "cookie", "authorization"}:
                    value = SECRET_REPLACEMENT
                lines.append(f"{key}: {self.redact(value)}\n")
        headers_path.write_text("".join(lines), encoding="utf-8")
        if store_body:
            body_path.write_text(self.redact(evidence.body_text()), encoding="utf-8")
        else:
            body_path.write_text(
                "[BODY OMITTED: authenticated page may contain draft body or other user content]\n",
                encoding="utf-8",
            )

    def write_text_evidence(self, label: str, text: str) -> str:
        path = self.evidence_dir / safe_label(label)
        path.write_text(self.redact(text), encoding="utf-8")
        return str(path.relative_to(self.run_dir))

    def redact(self, text: str) -> str:
        redacted = text
        for secret in self.secrets:
            if secret:
                redacted = redacted.replace(secret, SECRET_REPLACEMENT)
        redacted = re.sub(
            r"(?i)(osmap_session=)[A-Za-z0-9._~+/=-]+",
            r"\1[REDACTED]",
            redacted,
        )
        redacted = re.sub(
            r'(?i)(name=["\']csrf_token["\']\s+value=["\'])[^"\']+(["\'])',
            r"\1[REDACTED]\2",
            redacted,
        )
        redacted = re.sub(
            r"(?i)(csrf_token=)[^&\s\"']+",
            r"\1[REDACTED]",
            redacted,
        )
        redacted = re.sub(
            r'(?i)(name=["\']draft_id["\']\s+value=["\'])[0-9a-f]{32}(["\'])',
            r"\1[DRAFT_ID]\2",
            redacted,
        )
        redacted = re.sub(
            r"(?i)((?:/draft\?id=|draft_id=))[0-9a-f]{32}",
            r"\1[DRAFT_ID]",
            redacted,
        )
        redacted = re.sub(
            r"(?i)(authorization:\s*)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+",
            r"\1[REDACTED]",
            redacted,
        )
        return redacted

    def store_response_cookies(self, evidence: HttpEvidence) -> None:
        for header in evidence.header_values("Set-Cookie"):
            first = header.split(";", 1)[0]
            if "=" in first:
                name, value = first.split("=", 1)
                self.cookie_jar[name] = value

    def authenticated_ready(self) -> bool:
        return (
            self.config.allow_authenticated
            and bool(self.config.test_email)
            and (bool(self.config.test_password) or self.config.prompt_auth)
            and (bool(self.config.totp_secret) or self.config.prompt_auth)
        )

    def auth_password(self) -> str:
        if self.config.test_password:
            return self.config.test_password
        if not self.prompted_password:
            self.prompted_password = getpass.getpass(
                f"Password for {self.config.test_email}: "
            )
            if self.prompted_password:
                self.secrets.append(self.prompted_password)
        return self.prompted_password

    def auth_totp_code(self, reason: str) -> str:
        if self.config.totp_secret:
            self.authenticated_proof["totp"] = True
            return generate_totp(self.config.totp_secret)
        prompt = f"Current TOTP for {self.config.test_email} ({reason}): "
        code = getpass.getpass(prompt).strip().replace(" ", "")
        if code:
            self.secrets.append(code)
            self.authenticated_proof["totp"] = True
        return code

    def authenticated_login(
        self,
        label: str,
        *,
        cookies: dict[str, str] | None = None,
        reason: str = "login",
        store_cookies: bool = False,
    ) -> HttpEvidence:
        return self.form_post(
            label,
            "/login",
            {
                "username": self.config.test_email,
                "password": self.auth_password(),
                "totp_code": self.auth_totp_code(reason),
            },
            cookies=cookies,
            store_cookies=store_cookies,
        )

    def ensure_login(self) -> tuple[bool, str]:
        if self.authenticated:
            return True, "already authenticated"
        if not self.authenticated_ready():
            return False, "authenticated tests disabled or credentials/TOTP secret missing"
        evidence = self.authenticated_login(
            "auth_login",
            store_cookies=True,
            reason="primary authenticated WSTG session",
        )
        self.last_login_set_cookie_headers = evidence.header_values("Set-Cookie")
        if evidence.status != 303 or "osmap_session" not in self.cookie_jar:
            return False, f"login failed with HTTP {evidence.status}"
        self.authenticated_proof["login"] = True
        self.authenticated_proof["session_issued"] = True
        mailboxes = self.request(
            "auth_mailboxes",
            "GET",
            "/mailboxes",
            cookies=self.cookie_jar,
        )
        if mailboxes.status != 200:
            return False, f"mailbox check failed with HTTP {mailboxes.status}"
        self.authenticated_proof["protected_route_access"] = True
        self.csrf_token = extract_csrf(mailboxes.body_text())
        self.authenticated = True
        return True, "authenticated"

    def finalize_release_authentication_proof(self) -> list[str]:
        errors: list[str] = []
        if not self.config.release_mode:
            return errors
        if not self.authenticated:
            errors.append("release mode did not establish an authenticated session")
            return errors
        if not self.csrf_token:
            errors.append("release mode did not capture a CSRF token for logout proof")
            return errors
        logout = self.form_post(
            "auth_release_logout",
            "/logout",
            {"csrf_token": self.csrf_token},
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
        )
        if logout.status in {200, 303}:
            self.authenticated_proof["logout"] = True
        postlogout = self.request(
            "auth_release_postlogout_mailboxes",
            "GET",
            "/mailboxes",
            cookies=self.cookie_jar,
        )
        if postlogout.status != 200:
            self.authenticated_proof["session_invalidated"] = True
        for key, observed in self.authenticated_proof.items():
            if not observed:
                errors.append(f"release authenticated proof missing {key}")
        return errors

    def test_tls_and_redirect(self) -> TestResult:
        https = self.request("tls_https_login", "GET", "/login")
        if https.status != 200:
            return self.result(
                "OSMAP-WSTG-CONF-001",
                STATUS_FAIL,
                f"HTTPS /login did not return 200 (got {https.status or https.error})",
                ["evidence/tls_https_login.headers", "evidence/tls_https_login.body"],
            )
        http = self.request(
            "http_redirect",
            "GET",
            "/login",
            scheme="http",
            port=80,
        )
        if http.status in {301, 302, 307, 308}:
            location = http.first_header("Location")
            if location.startswith("https://") or location.startswith(self.config.base_url):
                return self.result(
                    "OSMAP-WSTG-CONF-001",
                    STATUS_PASS,
                    "HTTPS is available and HTTP redirects to HTTPS",
                    ["evidence/tls_https_login.headers", "evidence/http_redirect.headers"],
                    {"http_location": location},
                )
            return self.result(
                "OSMAP-WSTG-CONF-001",
                STATUS_FAIL,
                "HTTP redirect did not target HTTPS",
                ["evidence/http_redirect.headers"],
                {"http_location": location},
            )
        if http.status is None:
            return self.result(
                "OSMAP-WSTG-CONF-001",
                STATUS_PASS,
                "HTTPS is available and cleartext HTTP is not reachable",
                ["evidence/tls_https_login.headers", "evidence/http_redirect.headers"],
                {"http_error": http.error},
            )
        return self.result(
            "OSMAP-WSTG-CONF-001",
            STATUS_FAIL,
            f"HTTP returned unexpected status {http.status}",
            ["evidence/http_redirect.headers"],
        )

    def test_security_headers(self) -> TestResult:
        evidence = self.request("security_headers", "GET", "/login")
        required = {
            "strict-transport-security": lambda v: "max-age=" in v.lower(),
            "content-security-policy": lambda v: "default-src 'none'" in v.lower(),
            "x-frame-options": lambda v: v.lower() == "deny",
            "x-content-type-options": lambda v: v.lower() == "nosniff",
            "referrer-policy": lambda v: v.lower() == "no-referrer",
            "cross-origin-resource-policy": lambda v: v.lower() == "same-origin",
            "cache-control": lambda v: "no-store" in v.lower(),
        }
        missing: list[str] = []
        bad: list[str] = []
        for header, predicate in required.items():
            value = evidence.first_header(header)
            if not value:
                missing.append(header)
            elif not predicate(value):
                bad.append(f"{header}: {value}")
        if missing or bad:
            return self.result(
                "OSMAP-WSTG-CONF-002",
                STATUS_FAIL,
                "missing or weak browser security headers",
                ["evidence/security_headers.headers"],
                {"missing": missing, "bad": bad},
            )
        return self.result(
            "OSMAP-WSTG-CONF-002",
            STATUS_PASS,
            "required browser security headers are present",
            ["evidence/security_headers.headers"],
        )

    def test_csp(self) -> TestResult:
        evidence = self.request("csp", "GET", "/login")
        csp = evidence.first_header("Content-Security-Policy").lower()
        required = ["default-src 'none'", "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'"]
        if not csp:
            return self.result("OSMAP-WSTG-CONF-003", STATUS_FAIL, "CSP header missing", ["evidence/csp.headers"])
        missing = [token for token in required if token not in csp]
        risky = any(token in csp for token in ["script-src 'unsafe-inline'", "default-src *", "script-src *"])
        if missing or risky:
            return self.result(
                "OSMAP-WSTG-CONF-003",
                STATUS_FAIL,
                "CSP is missing required directives or allows risky script behavior",
                ["evidence/csp.headers"],
                {"missing": missing, "csp": csp},
            )
        return self.result("OSMAP-WSTG-CONF-003", STATUS_PASS, "CSP remains narrow and default-deny", ["evidence/csp.headers"])

    def test_sensitive_extension_and_backup_exposure(self) -> TestResult:
        probes = {
            "conf03_env": "/.env",
            "conf03_env_example": "/.env.example",
            "conf03_cargo_toml": "/Cargo.toml",
            "conf03_cargo_lock": "/Cargo.lock",
            "conf03_readme": "/README.md",
            "conf03_private_key": "/server.key",
            "conf03_certificate_key": "/mail.blackbagsecurity.com.key",
            "conf03_config_php": "/config.php",
            "conf03_nginx_conf": "/nginx.conf",
            "conf04_config_backup": "/config.php.bak",
            "conf04_index_backup": "/index.php~",
            "conf04_swap_file": "/.index.php.swp",
            "conf04_sql_backup": "/backup.sql",
            "conf04_archive_zip": "/backup.zip",
            "conf04_archive_tar": "/osmap.tar.gz",
            "conf04_old_env": "/.env.old",
        }
        sensitive_patterns = [
            r"(?i)BEGIN (?:RSA |OPENSSH |EC |)PRIVATE KEY",
            r"(?i)(?:password|passwd|secret|totp|session|csrf)[A-Z0-9_ -]*=",
            r"(?i)\[package\]",
            r"(?i)proxy_pass",
            r"(?i)server_name\s+mail\.blackbagsecurity\.com",
            r"(?i)CREATE TABLE|INSERT INTO",
        ]
        evidence_paths: list[str] = []
        statuses: dict[str, int | None] = {}
        failures: dict[str, object] = {}
        for label, path in probes.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            statuses[label] = evidence.status
            if evidence.status is not None and 200 <= evidence.status < 300:
                failures[f"{label}_served"] = evidence.status
            text = "\n".join(
                [evidence.body_text(), "\n".join(f"{key}: {value}" for key, value in evidence.headers)]
            )
            matches = [pattern for pattern in sensitive_patterns if re.search(pattern, text)]
            if matches:
                failures[f"{label}_sensitive_content"] = matches

        static_ok = self.write_sensitive_extension_and_backup_static_evidence()
        evidence_paths.append("evidence/sensitive_extension_backup_static.txt")
        if not static_ok:
            failures["static_boundary"] = "missing sensitive extension/backup exposure markers"
        if failures:
            return self.result(
                "OSMAP-WSTG-CONF-008",
                STATUS_FAIL,
                "sensitive extension, source, or backup probes exposed public content",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-CONF-008",
            STATUS_PASS,
            "sensitive extension, source, and backup probes were not served as public files",
            evidence_paths,
            {"statuses": statuses},
        )

    def write_sensitive_extension_and_backup_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "src" / "http_parse.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "docs" / "V3_CONFIG_DEPLOYMENT_EVIDENCE.md",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "sites-enabled" / "main-ssl.conf",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "templates" / "osmap-root.tmpl",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-CONF-008",
            "WSTG-v42-CONF-03",
            "WSTG-v42-CONF-04",
            "sensitive extension handling",
            "backup and unreferenced file exposure",
            "proxy_pass http://127.0.0.1:8080",
            "http_route_not_found",
            "request target path must not contain dot segments",
            "no public static repository root",
            "no public backup directory",
            "no source archive exposure",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Public file exposure decision:",
            "- The WAN OSMAP vhost proxies browser requests to the reviewed Rust router instead of serving the repository, Cargo files, environment templates, or deployment backups from a public static root.",
            "- Sensitive extension handling covers .env, .toml, .lock, .md, .key, .conf, .php, .bak, .old, .swp, .sql, .zip, and .tar.gz style probes.",
            "- Backup and unreferenced file exposure checks cover common editor backups, archive names, SQL dumps, old env files, and source/deployment filenames.",
            "- Dot-segment request targets fail in the HTTP parser before route handling.",
        ]
        self.write_text_evidence("sensitive_extension_backup_static.txt", "\n".join(lines) + "\n")
        return not missing

    def test_ria_cloud_storage_applicability(self) -> TestResult:
        probes = {
            "conf08_crossdomain_xml": "/crossdomain.xml",
            "conf08_clientaccesspolicy_xml": "/clientaccesspolicy.xml",
        }
        policy_patterns = [
            r"(?i)<cross-domain-policy\b",
            r"(?i)<allow-access-from\b",
            r"(?i)<allow-http-request-headers-from\b",
            r"(?i)<access-policy\b",
            r"(?i)<cross-domain-access\b",
        ]
        evidence_paths: list[str] = []
        statuses: dict[str, int | None] = {}
        failures: dict[str, object] = {}
        for label, path in probes.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            statuses[label] = evidence.status
            body = evidence.body_text()
            if evidence.status is not None and 200 <= evidence.status < 300:
                failures[f"{label}_served"] = evidence.status
            matches = [pattern for pattern in policy_patterns if re.search(pattern, body)]
            if matches:
                failures[f"{label}_policy_content"] = matches

        static_ok, static_findings = self.write_ria_cloud_storage_static_evidence()
        evidence_paths.append("evidence/ria_cloud_storage_static.txt")
        if not static_ok:
            failures["static_boundary"] = static_findings
        if failures:
            return self.result(
                "OSMAP-WSTG-CONF-009",
                STATUS_FAIL,
                "RIA policy or cloud storage applicability evidence found an exposed surface",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-CONF-009",
            STATUS_PASS,
            "RIA cross-domain policy and cloud storage are not applicable to the OSMAP browser surface",
            evidence_paths,
            {"statuses": statuses},
        )

    def write_ria_cloud_storage_static_evidence(self) -> tuple[bool, dict[str, object]]:
        boundary_files = [
            REPO_ROOT / "Cargo.toml",
            REPO_ROOT / "Cargo.lock",
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http" / "routes_auth.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "sites-enabled" / "main-ssl.conf",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "templates" / "osmap-root.tmpl",
        ]
        doc_file = REPO_ROOT / "docs" / "V3_CONFIG_DEPLOYMENT_EVIDENCE.md"
        forbidden = {
            "crossdomain.xml": r"(?i)\bcrossdomain\.xml\b",
            "clientaccesspolicy.xml": r"(?i)\bclientaccesspolicy\.xml\b",
            "aws_s3": r"(?i)\b(?:aws_access_key|s3\.amazonaws\.com|amazonaws\.com)\b",
            "gcp_storage": r"(?i)\b(?:storage\.googleapis\.com|googleapis\.com/storage)\b",
            "azure_blob": r"(?i)\b(?:blob\.core\.windows\.net|azure_storage)\b",
            "cloudfront": r"(?i)\bcloudfront\b",
        }
        findings: dict[str, list[str]] = {}
        for path in boundary_files:
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            hits = [name for name, pattern in forbidden.items() if re.search(pattern, text)]
            if hits:
                findings[str(path.relative_to(REPO_ROOT))] = hits
        doc_text = doc_file.read_text(encoding="utf-8", errors="replace") if doc_file.exists() else ""
        required_markers = [
            "OSMAP-WSTG-CONF-009",
            "WSTG-v42-CONF-08",
            "WSTG-v42-CONF-11",
            "no public RIA cross-domain policy",
            "no cloud object storage surface",
            "no cloud storage dependency",
        ]
        missing = [marker for marker in required_markers if marker.lower() not in doc_text.lower()]
        lines = [
            summarize_static_files(boundary_files + [doc_file], missing),
            "",
            "Applicability decisions:",
            "- RIA cross-domain policy is not applicable; OSMAP does not publish crossdomain.xml or clientaccesspolicy.xml and has no Flash, Silverlight, or RIA client boundary.",
            "- Cloud storage testing is not applicable; OSMAP does not use public S3, GCS, Azure Blob, CloudFront, or object-storage bucket endpoints for browser mail data.",
            "- The public WAN OSMAP vhost proxies browser routes to the Rust service rather than mounting a cloud bucket or static object-storage root.",
        ]
        if findings:
            lines.extend(["", "Unexpected cloud/RIA markers:", json.dumps(findings, indent=2)])
        self.write_text_evidence("ria_cloud_storage_static.txt", "\n".join(lines) + "\n")
        return not missing and not findings, {"missing_markers": missing, "unexpected_markers": findings}

    def test_file_permissions_and_subdomain_takeover(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-CONF-010", STATUS_SKIP, "host-assisted tests disabled")
        file_permissions = self.run_ssh(
            "host_file_permissions.txt",
            "doas stat -f '%Sp %u %g %N' "
            "/etc/osmap /etc/osmap/osmap-serve.env /etc/osmap/osmap-mailbox-helper.env "
            "/usr/local/bin/osmap /usr/local/libexec/osmap/osmap-serve-run.ksh "
            "/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh "
            "/etc/rc.d/osmap_serve /etc/rc.d/osmap_mailbox_helper "
            "/var/lib/osmap /var/lib/osmap/sessions /var/lib/osmap/settings "
            "/var/lib/osmap/audit /var/lib/osmap/cache /var/lib/osmap/secrets "
            "/var/lib/osmap/secrets/totp /var/lib/osmap-helper /var/lib/osmap-helper/run "
            "/var/lib/osmap-helper/sessions /var/lib/osmap-helper/settings "
            "/var/lib/osmap-helper/audit /var/lib/osmap-helper/cache "
            "/var/lib/osmap-helper/secrets /var/lib/osmap-helper/secrets/totp "
            "/var/lib/osmap-helper/run/mailbox-helper.sock 2>&1 || true",
        )
        dns = self.run_ssh(
            "subdomain_takeover_dns.txt",
            "for name in mail.blackbagsecurity.com webmail.blackbagsecurity.com osmap.blackbagsecurity.com; do "
            "printf '== %s ==\\n' \"$name\"; "
            "host -t CNAME \"$name\" 2>&1 || true; "
            "host -t A \"$name\" 2>&1 || true; "
            "host -t AAAA \"$name\" 2>&1 || true; "
            "done",
        )
        static_ok, static_findings = self.write_file_permission_subdomain_static_evidence()
        evidence = [
            "evidence/host_file_permissions.txt",
            "evidence/subdomain_takeover_dns.txt",
            "evidence/file_permission_subdomain_static.txt",
        ]
        if "ERROR:" in f"{file_permissions}\n{dns}":
            return self.result(
                "OSMAP-WSTG-CONF-010",
                STATUS_WARNING,
                "host-assisted file-permission or DNS evidence was unavailable from the current network path",
                evidence,
            )

        required_permission_markers = [
            "-rw-r----- 0 1001 /etc/osmap/osmap-serve.env",
            "-rw-r----- 0 2000 /etc/osmap/osmap-mailbox-helper.env",
            "-r-xr-xr-x 0 0 /usr/local/libexec/osmap/osmap-serve-run.ksh",
            "-r-xr-xr-x 0 0 /usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh",
            "-r-xr-xr-x 0 0 /etc/rc.d/osmap_serve",
            "-r-xr-xr-x 0 0 /etc/rc.d/osmap_mailbox_helper",
            "drwxr-x--- 1001 1001 /var/lib/osmap",
            "drwx------ 1001 1001 /var/lib/osmap/secrets/totp",
            "drwx--x--- 2000 1002 /var/lib/osmap-helper",
            "drwxrws--- 2000 1002 /var/lib/osmap-helper/run",
            "drwx------ 2000 2000 /var/lib/osmap-helper/secrets/totp",
            "srw-rw---- 2000 1002 /var/lib/osmap-helper/run/mailbox-helper.sock",
        ]
        missing_permissions = [marker for marker in required_permission_markers if marker not in file_permissions]
        required_dns_markers = [
            "mail.blackbagsecurity.com has no CNAME record",
            "mail.blackbagsecurity.com has address",
            "Host webmail.blackbagsecurity.com not found: 3(NXDOMAIN)",
            "Host osmap.blackbagsecurity.com not found: 3(NXDOMAIN)",
        ]
        missing_dns = [marker for marker in required_dns_markers if marker not in dns]
        dangling_patterns = [
            r"(?i)is an alias for .*amazonaws\.com",
            r"(?i)is an alias for .*azurewebsites\.net",
            r"(?i)is an alias for .*blob\.core\.windows\.net",
            r"(?i)is an alias for .*cloudapp\.net",
            r"(?i)is an alias for .*cloudfront\.net",
            r"(?i)is an alias for .*github\.io",
            r"(?i)is an alias for .*herokuapp\.com",
        ]
        dangling = [pattern for pattern in dangling_patterns if re.search(pattern, dns)]
        failures: dict[str, object] = {}
        if missing_permissions:
            failures["missing_permission_markers"] = missing_permissions
        if missing_dns:
            failures["missing_dns_markers"] = missing_dns
        if dangling:
            failures["dangling_cname_patterns"] = dangling
        if not static_ok:
            failures["static_boundary"] = static_findings
        if failures:
            return self.result(
                "OSMAP-WSTG-CONF-010",
                STATUS_FAIL,
                "file-permission or subdomain takeover evidence did not match the reviewed posture",
                evidence,
                failures,
            )
        return self.result(
            "OSMAP-WSTG-CONF-010",
            STATUS_PASS,
            "host permissions are restrictive and OSMAP public names have no dangling takeover CNAMEs",
            evidence,
        )

    def write_file_permission_subdomain_static_evidence(self) -> tuple[bool, dict[str, object]]:
        files = [
            REPO_ROOT / "maint" / "live" / "osmap-live-rehearse-service-enablement.ksh",
            REPO_ROOT / "maint" / "live" / "osmap-live-rehearse-service-artifacts.ksh",
            REPO_ROOT / "maint" / "openbsd" / "libexec" / "osmap-serve-run.ksh",
            REPO_ROOT / "maint" / "openbsd" / "libexec" / "osmap-mailbox-helper-run.ksh",
            REPO_ROOT / "maint" / "openbsd" / "rc.d" / "osmap_serve",
            REPO_ROOT / "maint" / "openbsd" / "rc.d" / "osmap_mailbox_helper",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "etc" / "osmap" / "osmap-serve.env",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "etc" / "osmap" / "osmap-mailbox-helper.env",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "sites-enabled" / "main-ssl.conf",
            REPO_ROOT / "docs" / "V3_CONFIG_DEPLOYMENT_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-CONF-010",
            "WSTG-v42-CONF-09",
            "WSTG-v42-CONF-10",
            "0640",
            "0555",
            "0750",
            "0700",
            "2770",
            "mail.blackbagsecurity.com",
            "no dangling takeover CNAME",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Configuration and deployment decisions:",
            "- File-permission evidence covers reviewed env files, launchers, rc.d files, state roots, secret directories, audit/cache directories, and the helper socket.",
            "- Service env files install as 0640; launchers and rc.d files install as 0555.",
            "- Serve state uses owner-only or _osmap-only directories; helper runtime uses the osmaprt shared group only where the web runtime needs the socket.",
            "- Subdomain takeover evidence covers mail.blackbagsecurity.com plus the unused OSMAP/webmail candidate names and requires no dangling takeover CNAME.",
        ]
        self.write_text_evidence("file_permission_subdomain_static.txt", "\n".join(lines) + "\n")
        return not missing, {"missing_markers": missing}

    def test_login_form(self) -> TestResult:
        evidence = self.request("login_form", "GET", "/login")
        body = evidence.body_text().lower()
        required_fields = ['name="username"', 'name="password"', 'name="totp_code"']
        missing = [field for field in required_fields if field not in body]
        if evidence.status != 200 or missing:
            return self.result(
                "OSMAP-WSTG-ATHN-001",
                STATUS_FAIL,
                "login form missing expected authentication fields",
                ["evidence/login_form.headers", "evidence/login_form.body"],
                {"http_status": evidence.status, "missing": missing},
            )
        if self.config.scheme != "https":
            return self.result("OSMAP-WSTG-ATHN-001", STATUS_FAIL, "login form was not requested over HTTPS")
        return self.result("OSMAP-WSTG-ATHN-001", STATUS_PASS, "login form exposes username, password, and TOTP fields over HTTPS", ["evidence/login_form.headers", "evidence/login_form.body"])

    def test_invalid_login(self) -> TestResult:
        unknown = self.form_post(
            "invalid_login_unknown_user",
            "/login",
            {"username": "wstg-unknown@example.invalid", "password": "bad-password", "totp_code": "000000"},
        )
        shaped_user = self.config.test_email or "wstg-shaped@example.invalid"
        shaped = self.form_post(
            "invalid_login_known_shape",
            "/login",
            {"username": shaped_user, "password": "bad-password", "totp_code": "000000"},
        )
        unknown_body = unknown.body_text()
        shaped_body = shaped.body_text()
        generic_marker = "The supplied credentials were not accepted."
        throttle_marker = "Too many login attempts were observed."
        statuses_ok = unknown.status in {401, 429} and shaped.status in {401, 429}
        generic = generic_marker in unknown_body and generic_marker in shaped_body
        throttled = throttle_marker in unknown_body or throttle_marker in shaped_body
        if statuses_ok and throttled:
            return self.result(
                "OSMAP-WSTG-ATHN-002",
                STATUS_WARNING,
                "login normalization probe was rate-limited before both generic failures could be compared",
                ["evidence/invalid_login_unknown_user.headers", "evidence/invalid_login_known_shape.headers"],
                {"unknown_status": unknown.status, "shaped_status": shaped.status},
            )
        if not statuses_ok or not generic:
            return self.result(
                "OSMAP-WSTG-ATHN-002",
                STATUS_FAIL,
                "invalid login behavior was not normalized",
                ["evidence/invalid_login_unknown_user.headers", "evidence/invalid_login_known_shape.headers"],
                {"unknown_status": unknown.status, "shaped_status": shaped.status, "generic_marker": generic},
            )
        return self.result("OSMAP-WSTG-ATHN-002", STATUS_PASS, "invalid login responses are generic and non-enumerating", ["evidence/invalid_login_unknown_user.headers", "evidence/invalid_login_known_shape.headers"])

    def test_throttle_probe(self) -> TestResult:
        statuses: list[int | None] = []
        throttled = False
        throttle_domain = (
            self.config.test_email.rsplit("@", 1)[1]
            if "@" in self.config.test_email
            else self.config.host
        )
        throttle_username = f"wstg-throttle@{throttle_domain}"
        for attempt in range(1, self.config.throttle_attempts + 1):
            evidence = self.form_post(
                f"throttle_probe_attempt_{attempt}",
                "/login",
                {
                    "username": throttle_username,
                    "password": f"bad-password-{attempt}",
                    "totp_code": "000000",
                },
            )
            statuses.append(evidence.status)
            if evidence.status == 429 or "Too many login attempts" in evidence.body_text():
                throttled = True
            time.sleep(self.config.rate_delay)
        evidence_names = [f"evidence/throttle_probe_attempt_{i}.headers" for i in range(1, self.config.throttle_attempts + 1)]
        if any(status not in {401, 429, None} for status in statuses):
            return self.result(
                "OSMAP-WSTG-ATHN-003",
                STATUS_FAIL,
                "throttle probe saw unexpected login response status",
                evidence_names,
                {"statuses": statuses},
            )
        if any(status is None for status in statuses):
            return self.result(
                "OSMAP-WSTG-ATHN-003",
                STATUS_WARNING,
                "bounded probe included a timeout; no unsafe retry amplification was performed",
                evidence_names,
                {"statuses": statuses, "attempts": self.config.throttle_attempts},
            )
        if throttled:
            return self.result("OSMAP-WSTG-ATHN-003", STATUS_PASS, "bounded probe observed login throttling", evidence_names, {"statuses": statuses})
        return self.result(
            "OSMAP-WSTG-ATHN-003",
            STATUS_WARNING,
            "bounded probe did not reach the throttle threshold; no unsafe extra attempts were made",
            evidence_names,
            {"statuses": statuses, "attempts": self.config.throttle_attempts},
        )

    def test_authenticated_login(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-ATHN-004", STATUS_SKIP, message)
        return self.result("OSMAP-WSTG-ATHN-004", STATUS_PASS, "authenticated login and mailbox access succeeded", ["evidence/auth_login.headers", "evidence/auth_mailboxes.headers"])

    def test_session_cookie_flags(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-SESS-001", STATUS_SKIP, message)
        cookie_headers = self.last_login_set_cookie_headers
        cookie = "\n".join(cookie_headers).lower()
        flags = ["httponly", "secure", "samesite=strict", "path=/"]
        missing = [flag for flag in flags if flag not in cookie]
        if missing:
            return self.result(
                "OSMAP-WSTG-SESS-001",
                STATUS_FAIL,
                "session cookie is missing required flags",
                ["evidence/auth_login.headers"],
                {"missing": missing},
            )
        return self.result("OSMAP-WSTG-SESS-001", STATUS_PASS, "session cookie has Secure, HttpOnly, SameSite=Strict, and Path=/", ["evidence/auth_login.headers"])

    def test_session_fixation(self) -> TestResult:
        if not self.authenticated_ready():
            return self.result("OSMAP-WSTG-SESS-002", STATUS_SKIP, "authenticated tests disabled or credentials/TOTP secret missing")
        fixed = "f" * 64
        evidence = self.authenticated_login(
            "session_fixation",
            cookies={"osmap_session": fixed},
            reason="session fixation check",
        )
        cookie_values = evidence.header_values("Set-Cookie")
        retained = any(f"osmap_session={fixed}" in value for value in cookie_values)
        if evidence.status != 303 or retained:
            return self.result("OSMAP-WSTG-SESS-002", STATUS_FAIL, "pre-login session value was retained or login failed", ["evidence/session_fixation.headers"], {"http_status": evidence.status})
        cleanup_jar = cookie_jar_from_set_cookie_headers(cookie_values)
        if "osmap_session" in cleanup_jar:
            cleanup_page = self.request(
                "session_fixation_cleanup_mailboxes",
                "GET",
                "/mailboxes",
                cookies=cleanup_jar,
            )
            cleanup_csrf = extract_csrf(cleanup_page.body_text())
            if cleanup_csrf:
                self.form_post(
                    "session_fixation_cleanup_logout",
                    "/logout",
                    {"csrf_token": cleanup_csrf},
                    cookies=cleanup_jar,
                    headers=same_origin_headers(self.config),
                )
        return self.result("OSMAP-WSTG-SESS-002", STATUS_PASS, "authentication issued a fresh session cookie", ["evidence/session_fixation.headers"])

    def test_logout_csrf(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-SESS-003", STATUS_SKIP, message)
        missing = self.form_post(
            "logout_missing_csrf",
            "/logout",
            {},
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
        )
        postcheck = self.request("logout_postcheck", "GET", "/mailboxes", cookies=self.cookie_jar)
        if missing.status != 403 or postcheck.status != 200:
            return self.result(
                "OSMAP-WSTG-SESS-003",
                STATUS_FAIL,
                "logout without CSRF was not rejected while preserving session",
                ["evidence/logout_missing_csrf.headers", "evidence/logout_postcheck.headers"],
                {"logout_status": missing.status, "postcheck_status": postcheck.status},
            )
        return self.result("OSMAP-WSTG-SESS-003", STATUS_PASS, "logout requires CSRF token and preserved the session after rejection", ["evidence/logout_missing_csrf.headers", "evidence/logout_postcheck.headers"])

    def test_authenticated_csrf(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-SESS-004", STATUS_SKIP, message)
        missing = self.form_post(
            "csrf_settings_missing",
            "/settings",
            {"html_display_preference": "prefer_plain_text"},
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
        )
        cross = self.form_post(
            "csrf_settings_cross_origin",
            "/settings",
            {"csrf_token": self.csrf_token, "html_display_preference": "prefer_plain_text"},
            cookies=self.cookie_jar,
            headers={"Origin": "https://attacker.invalid"},
        )
        if missing.status != 403 or cross.status != 403:
            return self.result(
                "OSMAP-WSTG-SESS-004",
                STATUS_FAIL,
                "settings mutation did not reject missing CSRF or cross-origin metadata",
                ["evidence/csrf_settings_missing.headers", "evidence/csrf_settings_cross_origin.headers"],
                {"missing_status": missing.status, "cross_origin_status": cross.status},
            )
        return self.result("OSMAP-WSTG-SESS-004", STATUS_PASS, "authenticated mutation rejects missing CSRF and cross-origin metadata", ["evidence/csrf_settings_missing.headers", "evidence/csrf_settings_cross_origin.headers"])

    def test_authenticated_cache_control(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-SESS-005", STATUS_SKIP, message)
        settings = self.request("auth_settings", "GET", "/settings", cookies=self.cookie_jar)
        values = [settings.first_header("Cache-Control")]
        mailboxes_headers = (self.evidence_dir / "auth_mailboxes.headers").read_text(encoding="utf-8").lower()
        if "cache-control: no-store" not in mailboxes_headers or any("no-store" not in value.lower() for value in values):
            return self.result("OSMAP-WSTG-SESS-005", STATUS_FAIL, "authenticated pages are missing Cache-Control: no-store", ["evidence/auth_mailboxes.headers", "evidence/auth_settings.headers"])
        return self.result("OSMAP-WSTG-SESS-005", STATUS_PASS, "authenticated pages suppress browser cache storage", ["evidence/auth_mailboxes.headers", "evidence/auth_settings.headers"])

    def test_session_lifecycle_policy(self) -> TestResult:
        if not self.authenticated_ready():
            return self.result("OSMAP-WSTG-SESS-006", STATUS_SKIP, "authenticated tests disabled or credentials/TOTP secret missing")
        login = self.authenticated_login(
            "session_lifecycle_login",
            reason="session lifecycle policy check",
        )
        cookie_jar = cookie_jar_from_set_cookie_headers(login.header_values("Set-Cookie"))
        mailboxes = self.request(
            "session_lifecycle_mailboxes",
            "GET",
            "/mailboxes",
            cookies=cookie_jar,
        )
        csrf_token = extract_csrf(mailboxes.body_text())
        logout = self.form_post(
            "session_lifecycle_logout",
            "/logout",
            {"csrf_token": csrf_token},
            cookies=cookie_jar,
            headers=same_origin_headers(self.config),
            store_body_evidence=False,
        )
        old_cookie = self.request(
            "session_lifecycle_old_cookie_after_logout",
            "GET",
            "/mailboxes",
            cookies=cookie_jar,
            store_body_evidence=False,
        )
        stale_cookie = self.request(
            "session_lifecycle_stale_cookie",
            "GET",
            "/mailboxes",
            cookies={"osmap_session": "d" * 64},
            store_body_evidence=False,
        )
        static_ok = self.write_session_lifecycle_static_evidence()
        redaction_ok = self.write_session_lifecycle_redaction_evidence([csrf_token])
        statuses = {
            "login": login.status,
            "mailboxes": mailboxes.status,
            "logout": logout.status,
            "old_cookie_after_logout": old_cookie.status,
            "stale_cookie": stale_cookie.status,
        }
        failures: dict[str, object] = {}
        if login.status != 303 or "osmap_session" not in cookie_jar:
            failures["login"] = login.status
        if mailboxes.status != 200 or not csrf_token:
            failures["mailboxes"] = mailboxes.status
        if logout.status not in {200, 303}:
            failures["logout"] = logout.status
        if old_cookie.status == 200:
            failures["old_cookie_after_logout"] = old_cookie.status
        if stale_cookie.status == 200:
            failures["stale_cookie"] = stale_cookie.status
        if not static_ok:
            failures["static_boundary"] = "missing session lifecycle markers"
        if not redaction_ok:
            failures["redaction"] = "session lifecycle evidence redaction scan failed"
        evidence_paths = [
            "evidence/session_lifecycle_login.headers",
            "evidence/session_lifecycle_mailboxes.headers",
            "evidence/session_lifecycle_mailboxes.body",
            "evidence/session_lifecycle_logout.headers",
            "evidence/session_lifecycle_old_cookie_after_logout.headers",
            "evidence/session_lifecycle_stale_cookie.headers",
            "evidence/session_lifecycle_static.txt",
            "evidence/session_lifecycle_redaction.txt",
        ]
        if failures:
            return self.result(
                "OSMAP-WSTG-SESS-006",
                STATUS_FAIL,
                "session lifecycle evidence did not meet expected outcomes",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-SESS-006",
            STATUS_PASS,
            "session lifecycle evidence covers logout invalidation, stale-cookie rejection, timeout policy, exposed-token controls, concurrent-session policy, and race handling",
            evidence_paths,
            {"statuses": statuses},
        )

    def write_session_lifecycle_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "session.rs",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "docs" / "SESSION_MANAGEMENT_MODEL.md",
            REPO_ROOT / "docs" / "V3_SECURITY_GATES.md",
            REPO_ROOT / "docs" / "V3_SESSION_LIFECYCLE_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS",
            "timeout_reason",
            "validate_session_rejects_expired_records",
            "validate_session_auto_revokes_idle_records",
            "list_sessions_auto_revokes_idle_records",
            "simultaneous_session_validations_do_not_corrupt_last_seen",
            "logout_racing_with_validation_leaves_session_revoked",
            "revoke_all_racing_with_listing_leaves_all_sessions_revoked",
            "revoke_all_for_user_except_preserves_current_session",
            "raw bearer tokens are not written",
            "concurrent browser sessions are allowed by policy",
            "remembered-device cookies",
            "OSMAP-WSTG-SESS-006",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "session_lifecycle_static.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- absolute and idle timeout revocation are enforced during validation/listing\n"
            + "- logout revokes server-side session state and stale cookies fail closed\n"
            + "- concurrent sessions are allowed by policy and remain user-revocable\n"
            + "- same-process race tests cover validation, logout, listing, and revoke-all state transitions\n"
            + "- raw bearer tokens are not stored and browser-visible metadata avoids remembered-device identifiers\n",
        )
        return not missing

    def write_session_lifecycle_redaction_evidence(self, forbidden_values: list[str]) -> bool:
        leaks: dict[str, list[str]] = {}
        forbidden_patterns = [
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
            ("csrf_token_value", r"(?i)csrf_token=[A-Za-z0-9._~+/=-]{16,}"),
            ("session_response_cookie_value", r"(?i)" + "set" + r"-cookie: .*?[a-f0-9]{64}"),
        ]
        for value in forbidden_values:
            if value:
                forbidden_patterns.append((f"value_{len(forbidden_patterns)}", re.escape(value)))
        for path in sorted(self.evidence_dir.glob("session_lifecycle_*")):
            if path.name == "session_lifecycle_redaction.txt":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, text)]
            if matches:
                leaks[path.name] = matches
        lines = [
            "Session lifecycle evidence redaction scan:",
            "- checked session_lifecycle_* evidence files only",
            "- raw session cookies, response cookie bearer values, and CSRF token values must be absent",
        ]
        if leaks:
            lines.append("Leaks detected:")
            for path, matches in leaks.items():
                lines.append(f"- {path}: {', '.join(matches)}")
        else:
            lines.append("result=passed")
        self.write_text_evidence("session_lifecycle_redaction.txt", "\n".join(lines) + "\n")
        return not leaks

    def test_methods(self) -> TestResult:
        options = self.request("method_options", "OPTIONS", "/login")
        trace = self.request("method_trace", "TRACE", "/login", headers={"X-OSMAP-WSTG-Trace": "trace-probe"})
        bad_status = [status for status in [options.status, trace.status] if status is not None and 200 <= status < 300]
        echoed = "trace-probe" in trace.body_text()
        if bad_status or echoed:
            return self.result(
                "OSMAP-WSTG-CONF-004",
                STATUS_FAIL,
                "unsupported method was accepted or TRACE echoed request content",
                ["evidence/method_options.headers", "evidence/method_trace.headers", "evidence/method_trace.body"],
                {"options_status": options.status, "trace_status": trace.status, "trace_echoed": echoed},
            )
        return self.result("OSMAP-WSTG-CONF-004", STATUS_PASS, "OPTIONS and TRACE are not accepted as application methods", ["evidence/method_options.headers", "evidence/method_trace.headers"])

    def test_metafiles(self) -> TestResult:
        robots = self.request("robots_txt", "GET", "/robots.txt")
        security = self.request("security_txt", "GET", "/.well-known/security.txt")
        combined = f"{robots.body_text()}\n{security.body_text()}"
        dangerous = re.findall(r"(?i)(password|secret|private key|/var/|/etc/|totp|session)", combined)
        if dangerous:
            return self.result("OSMAP-WSTG-INFO-001", STATUS_FAIL, "metafile response disclosed sensitive-looking tokens", ["evidence/robots_txt.body", "evidence/security_txt.body"], {"matches": sorted(set(dangerous))})
        return self.result("OSMAP-WSTG-INFO-001", STATUS_PASS, "robots.txt and security.txt did not disclose sensitive paths or secrets", ["evidence/robots_txt.headers", "evidence/security_txt.headers"])

    def test_info_disclosure(self) -> TestResult:
        probes = {
            "info_disclosure_login": "/login",
            "info_disclosure_missing": "/does-not-exist-wstg",
            "info_disclosure_bad_query": "/message?mailbox=INBOX&uid=not-a-number",
        }
        evidence_paths: list[str] = []
        leaked: dict[str, list[str]] = {}
        patterns = [
            r"(?i)panic",
            r"(?i)stack backtrace",
            r"(?i)rust_backtrace",
            r"(?i)/home/[A-Za-z0-9_/-]+",
            r"(?i)/var/lib/osmap",
            r"(?i)totp[_ -]?secret",
            r"(?i)private key",
            r"(?i)password=",
        ]
        for label, path in probes.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            text = "\n".join([evidence.body_text(), "\n".join(f"{k}: {v}" for k, v in evidence.headers)])
            matches = [pattern for pattern in patterns if re.search(pattern, text)]
            if matches:
                leaked[label] = matches
        if leaked:
            return self.result("OSMAP-WSTG-INFO-002", STATUS_FAIL, "unauthenticated response disclosed sensitive diagnostic content", evidence_paths, {"matches": leaked})
        return self.result("OSMAP-WSTG-INFO-002", STATUS_PASS, "unauthenticated pages and errors did not expose sensitive diagnostics", evidence_paths)

    def test_error_and_route_inventory(self) -> TestResult:
        probes = {
            "errh02_missing_route": "/does-not-exist-wstg-slice9",
            "errh02_bad_uid": "/message?mailbox=INBOX&uid=not-a-number",
            "errh02_bad_mailbox": "/mailbox?name=",
            "errh02_bad_attachment": "/attachment?mailbox=INBOX&uid=not-a-number&part=1.2",
            "errh02_bad_search": "/search?q=",
        }
        leak_patterns = [
            r"(?i)\bpanic(?:ked)?\b",
            r"(?i)stack backtrace",
            r"(?i)rust_backtrace",
            r"(?i)thread '.*' panicked",
            r"(?i)traceback \(most recent call last\)",
            r"(?i)src/[A-Za-z0-9_./-]+\.rs:\d+",
            r"(?i)/home/[A-Za-z0-9_./-]+",
            r"(?i)/var/(?:lib|www|log)/[A-Za-z0-9_./-]+",
            r"(?i)called `(?:Option::unwrap|Result::unwrap|expect)`",
        ]
        evidence_paths: list[str] = []
        leaked: dict[str, list[str]] = {}
        statuses: dict[str, int | None] = {}
        for label, path in probes.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            statuses[label] = evidence.status
            text = "\n".join(
                [evidence.body_text(), "\n".join(f"{key}: {value}" for key, value in evidence.headers)]
            )
            matches = [pattern for pattern in leak_patterns if re.search(pattern, text)]
            if matches:
                leaked[label] = matches

        static_ok = self.write_error_and_route_inventory_static_evidence()
        evidence_paths.append("evidence/error_route_inventory_static.txt")
        failures: dict[str, object] = {}
        if leaked:
            failures["diagnostic_leaks"] = leaked
        if not static_ok:
            failures["static_boundary"] = "missing error/route inventory markers"
        if failures:
            return self.result(
                "OSMAP-WSTG-INFO-003",
                STATUS_FAIL,
                "error responses or route inventory evidence exposed stack/architecture leakage risk",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-INFO-003",
            STATUS_PASS,
            "stack-trace probes stayed generic and the browser route/architecture inventory is documented",
            evidence_paths,
            {"statuses": statuses},
        )

    def write_error_and_route_inventory_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http" / "routes_auth.rs",
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http" / "routes_draft.rs",
            REPO_ROOT / "src" / "http" / "routes_settings.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "src" / "mailbox_helper_client.rs",
            REPO_ROOT / "src" / "mailbox_backend.rs",
            REPO_ROOT / "src" / "send.rs",
            REPO_ROOT / "docs" / "ARCHITECTURE.md",
            REPO_ROOT / "docs" / "V3_ERROR_INFO_DISCLOSURE_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-INFO-003",
            "WSTG-v42-ERRH-02",
            "WSTG-v42-INFO-06",
            "WSTG-v42-INFO-07",
            "WSTG-v42-INFO-10",
            "handle_request",
            "http_route_not_found",
            "The requested path does not exist in the current OSMAP browser slice.",
            "Request context could not be validated.",
            "public_reason_message",
            "/login",
            "/mailboxes",
            "/mailbox",
            "/search",
            "/message",
            "/attachment",
            "/compose",
            "/drafts",
            "/draft",
            "/sessions",
            "/settings",
            "/message/move",
            "/messages/move",
            "/messages/archive",
            "/send",
            "/drafts/save",
            "/drafts/delete",
            "/sessions/revoke",
            "/logout",
            "nginx edge",
            "Postfix",
            "Dovecot",
            "Rspamd",
            "mailbox helper",
            "sendmail",
            "stack traces are not browser-visible",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        route_inventory = [
            "GET /healthz -> health check",
            "GET /login and POST /login -> authentication",
            "GET / and GET /mailboxes -> mailbox landing",
            "GET /mailbox, /search, /message, /attachment -> mailbox read paths",
            "GET /compose, /drafts, /draft -> compose and draft read paths",
            "GET /sessions and /settings -> account settings read paths",
            "POST /message/move, /messages/move, /messages/archive -> message state changes",
            "POST /send, /drafts/save, /drafts/delete -> compose and draft state changes",
            "POST /sessions/revoke, /settings, /logout -> session/settings state changes",
        ]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Browser route inventory:",
            *[f"- {item}" for item in route_inventory],
            "",
            "Architecture inventory:",
            "- Public HTTPS and response-header policy terminate at the nginx edge.",
            "- OSMAP is the Rust browser access layer; it uses bounded form routes, no JSON/GraphQL API, and no client-side scripting dependency.",
            "- Authentication/session decisions use local auth, TOTP, filesystem-backed session state, and CSRF-bound browser forms.",
            "- Mailbox reads and moves cross a mailbox helper or doveadm boundary; sending hands off through sendmail to the existing Postfix/Dovecot/Rspamd mail stack.",
            "",
            "Error disclosure decision:",
            "- Stack traces are not browser-visible: public error bodies use stable generic messages, while detailed failure reasons stay in structured audit events and redacted WSTG evidence.",
        ]
        self.write_text_evidence("error_route_inventory_static.txt", "\n".join(lines) + "\n")
        return not missing

    def test_public_reconnaissance_fingerprinting(self) -> TestResult:
        expected_public = {
            "info_recon_root": "/",
            "info_recon_login": "/login",
            "info_recon_healthz": "/healthz",
            "info_recon_robots": "/robots.txt",
            "info_recon_security": "/.well-known/security.txt",
        }
        common_unexpected = {
            "info_recon_admin": "/admin",
            "info_recon_api": "/api",
            "info_recon_graphql": "/graphql",
            "info_recon_phpmyadmin": "/phpmyadmin",
            "info_recon_roundcube": "/roundcube",
            "info_recon_webmail": "/webmail",
            "info_recon_git_config": "/.git/config",
            "info_recon_server_status": "/server-status",
        }
        framework_patterns = [
            r"(?i)\bx-powered-by\b",
            r"(?i)\b(?:actix|axum|rocket|warp|hyper|django|flask|rails|laravel|express|next\.js|phpmyadmin|roundcube)\b",
            r"(?i)\b(?:apache|nginx|opensmtpd|dovecot|postfix|rspamd)/\d",
            r"(?i)\bserver: [^\n\r]+/\d",
        ]
        evidence_paths: list[str] = []
        failures: dict[str, object] = {}
        statuses: dict[str, int | None] = {}
        for label, path in {**expected_public, **common_unexpected}.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            statuses[label] = evidence.status
            text = "\n".join(
                [evidence.body_text(), "\n".join(f"{key}: {value}" for key, value in evidence.headers)]
            )
            matches = [pattern for pattern in framework_patterns if re.search(pattern, text)]
            if matches:
                failures[f"{label}_fingerprint"] = matches
            if label in common_unexpected and evidence.status is not None and 200 <= evidence.status < 300:
                failures[f"{label}_unexpected_public_app"] = evidence.status

        static_ok = self.write_public_reconnaissance_fingerprinting_static_evidence()
        evidence_paths.append("evidence/public_recon_fingerprinting_static.txt")
        if not static_ok:
            failures["static_boundary"] = "missing public reconnaissance/fingerprinting markers"
        if failures:
            return self.result(
                "OSMAP-WSTG-INFO-004",
                STATUS_FAIL,
                "public reconnaissance or fingerprinting probes exposed unexpected app or framework signals",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-INFO-004",
            STATUS_PASS,
            "bounded public reconnaissance found only expected OSMAP entry points and no framework/version fingerprints",
            evidence_paths,
            {"statuses": statuses},
        )

    def write_public_reconnaissance_fingerprinting_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "src" / "http_ui.rs",
            REPO_ROOT / "src" / "config.rs",
            REPO_ROOT / "docs" / "V3_ERROR_INFO_DISCLOSURE_EVIDENCE.md",
            REPO_ROOT / "docs" / "ARCHITECTURE.md",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "sites-enabled" / "main-ssl.conf",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "templates" / "osmap-root.tmpl",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-INFO-004",
            "WSTG-v42-INFO-01",
            "WSTG-v42-INFO-04",
            "WSTG-v42-INFO-08",
            "WSTG-v42-INFO-09",
            "bounded public reconnaissance",
            "public app enumeration",
            "framework fingerprinting",
            "web application fingerprinting",
            "search engine discovery reconnaissance",
            "GET /login",
            "GET /healthz",
            "GET /robots.txt",
            "GET /.well-known/security.txt",
            "no X-Powered-By",
            "no framework version banner",
            "no secondary webmail app",
            "OSMAP Login",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Bounded public reconnaissance:",
            "- Expected public entry points are /, /login, /healthz, /robots.txt, and /.well-known/security.txt.",
            "- Common secondary application paths such as /admin, /api, /graphql, /phpmyadmin, /roundcube, /webmail, /.git/config, and /server-status must not expose another public app.",
            "- Search engine discovery reconnaissance is represented by the same public-footprint evidence plus robots/security metadata review; committed evidence must not depend on a mutable third-party search result page.",
            "",
            "Fingerprinting decision:",
            "- Public responses must not expose X-Powered-By, framework version banners, Rust web-framework names, or backend mail-stack version strings.",
            "- The intended web application fingerprint is the OSMAP login/mailbox browser surface only; no secondary webmail app is part of this boundary.",
        ]
        self.write_text_evidence("public_recon_fingerprinting_static.txt", "\n".join(lines) + "\n")
        return not missing

    def test_path_traversal(self) -> TestResult:
        bad: dict[str, int | None] = {}
        truncated: list[str] = []
        evidence_paths: list[str] = []
        for label, path in PATH_TRAVERSAL_PROBES.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            body = evidence.body_text().lower()
            if evidence.truncated:
                truncated.append(label)
            if evidence.status == 200 or "root:" in body or "/bin/" in body or "osmap_session" in body:
                bad[label] = evidence.status
        if truncated:
            return self.result("OSMAP-WSTG-INPV-001", STATUS_FAIL, "path traversal evidence was truncated before sensitive-content checks completed", evidence_paths, {"truncated": truncated})
        if bad:
            return self.result("OSMAP-WSTG-INPV-001", STATUS_FAIL, "path traversal probe reached sensitive-looking content or succeeded", evidence_paths, {"bad": bad})
        return self.result("OSMAP-WSTG-INPV-001", STATUS_PASS, "path traversal probes were rejected or safely gated", evidence_paths)

    def test_reflected_input(self) -> TestResult:
        bad: list[str] = []
        truncated: list[str] = []
        evidence_paths: list[str] = []
        route_templates = {
            "login": "/login?probe={payload}",
            "search": "/search?q={payload}",
            "mailbox": "/mailbox?name={payload}",
        }
        dangerous = ["<script", "onerror=", "onfocus=", "javascript:"]
        for index, payload in enumerate(REFLECTED_INPUT_PAYLOADS, start=1):
            encoded = urllib.parse.quote(payload, safe="")
            for route, template in route_templates.items():
                label = f"reflected_input_{route}_{index}"
                evidence = self.request(label, "GET", template.format(payload=encoded))
                body = evidence.body_text().lower()
                evidence_paths.append(f"evidence/{label}.body")
                if evidence.truncated:
                    truncated.append(label)
                if any(token in body for token in dangerous):
                    bad.append(label)
        if truncated:
            return self.result("OSMAP-WSTG-INPV-002", STATUS_FAIL, "reflected-input evidence was truncated before executable-markup checks completed", evidence_paths, {"truncated": truncated})
        if bad:
            return self.result("OSMAP-WSTG-INPV-002", STATUS_FAIL, "probe payload was reflected as executable markup", evidence_paths, {"bad": bad})
        return self.result("OSMAP-WSTG-INPV-002", STATUS_PASS, "probe payloads were not reflected as executable markup", evidence_paths)

    def test_command_injection(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-INPV-003", STATUS_SKIP, message)

        nonce = hashlib.sha256(f"inpv12:{time.time()}:{os.getpid()}".encode("utf-8")).hexdigest()[:12]
        input_marker = f"OSMAP_INPV12_INPUT_{nonce}"
        output_canary = f"OSMAP_INPV12_OUTPUT_{nonce}"
        payloads = command_injection_payloads(input_marker, output_canary)
        surfaces = command_injection_surfaces(self.config, self.csrf_token)
        baseline_by_surface: dict[str, float] = {}
        findings: dict[str, list[str]] = {}
        statuses: dict[str, int | None] = {}
        elapsed: dict[str, float] = {}
        evidence_paths: list[str] = []

        for surface in surfaces:
            baseline_label = f"command_injection_baseline_{surface['name']}"
            baseline_started = time.monotonic()
            baseline = self.command_injection_surface_request(
                baseline_label,
                surface,
                input_marker,
                cookies=self.cookie_jar if surface["authenticated"] else None,
            )
            baseline_elapsed = time.monotonic() - baseline_started
            baseline_by_surface[surface["name"]] = baseline_elapsed
            evidence_paths.extend([
                f"evidence/{baseline_label}.headers",
                f"evidence/{baseline_label}.body",
            ])
            statuses[baseline_label] = baseline.status
            elapsed[baseline_label] = round(baseline_elapsed, 3)

        for surface in surfaces:
            baseline_elapsed = baseline_by_surface[surface["name"]]
            for payload in payloads:
                label = f"command_injection_{surface['name']}_{payload['name']}"
                started = time.monotonic()
                evidence = self.command_injection_surface_request(
                    label,
                    surface,
                    str(payload["payload"]),
                    cookies=self.cookie_jar if surface["authenticated"] else None,
                )
                probe_elapsed = time.monotonic() - started
                evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
                statuses[label] = evidence.status
                elapsed[label] = round(probe_elapsed, 3)
                probe_findings = command_injection_findings(
                    evidence,
                    raw_payload=str(payload["payload"]),
                    output_canary=output_canary,
                    elapsed=probe_elapsed,
                    baseline_elapsed=baseline_elapsed,
                    timing_probe=bool(payload["timing_probe"]),
                )
                if probe_findings:
                    findings[label] = probe_findings
                time.sleep(min(self.config.rate_delay, 0.25))

        host_evidence = ""
        if self.config.allow_host_assisted:
            host_evidence = self.command_injection_host_evidence(nonce)
            evidence_paths.append("evidence/command_injection_host_evidence.txt")
            host_findings = command_injection_text_findings(
                host_evidence,
                output_canary=output_canary,
                source_payloads=[str(item["payload"]) for item in payloads],
            )
            if host_findings:
                findings["host_logs"] = host_findings

        matrix_path = self.write_command_injection_matrix_evidence(
            nonce,
            payloads,
            surfaces,
            statuses,
            elapsed,
            findings,
        )
        redaction_path = self.write_command_injection_redaction_evidence(nonce)
        evidence_paths.extend([matrix_path, redaction_path])

        if findings:
            return self.result(
                "OSMAP-WSTG-INPV-003",
                STATUS_FAIL,
                "safe command-injection probes found shell execution, diagnostic leakage, truncation, HTTP 500, or timing evidence",
                evidence_paths,
                {"nonce": nonce, "findings": findings},
            )
        return self.result(
            "OSMAP-WSTG-INPV-003",
            STATUS_PASS,
            "safe command-injection due-diligence probes across unauthenticated and authenticated OSMAP surfaces found no shell execution, diagnostic leakage, truncation, HTTP 500, or abnormal timing",
            evidence_paths,
            {"nonce": nonce, "probed_surfaces": [surface["name"] for surface in surfaces]},
        )

    def command_injection_surface_request(
        self,
        label: str,
        surface: dict[str, object],
        payload: str,
        *,
        cookies: dict[str, str] | None,
    ) -> HttpEvidence:
        method = str(surface["method"])
        path_template = str(surface["path"])
        headers = dict(surface.get("headers", {}))
        fields = dict(surface.get("fields", {}))
        path = path_template.format(payload=urllib.parse.quote(payload, safe=""))
        if fields:
            body_fields = {
                key: str(value).format(payload=payload)
                for key, value in fields.items()
            }
            return self.form_post(
                label,
                path,
                body_fields,
                cookies=cookies,
                headers=headers,
            )
        return self.request(label, method, path, headers=headers, cookies=cookies)

    def command_injection_host_evidence(self, nonce: str) -> str:
        quoted_nonce = shlex.quote(nonce)
        command = (
            "set -eu; "
            f"nonce={quoted_nonce}; "
            "printf '%s\\n' '--- services after OSMAP-WSTG-INPV-003 ---'; "
            "hostname; rcctl check nginx || true; rcctl check osmap_serve || true; rcctl check osmap_mailbox_helper || true; "
            "printf '%s\\n' '--- nginx access log nonce matches ---'; "
            "doas grep -F \"$nonce\" /var/log/nginx/mail.access.log 2>/dev/null | tail -40 || true; "
            "printf '%s\\n' '--- nginx error log nonce matches ---'; "
            "doas grep -F \"$nonce\" /var/log/nginx/mail.error.log 2>/dev/null | tail -40 || true; "
            "printf '%s\\n' '--- osmap serve log nonce matches ---'; "
            "doas grep -F \"$nonce\" /var/lib/osmap/audit/serve.log 2>/dev/null | tail -80 || true; "
            "printf '%s\\n' '--- osmap helper log nonce matches ---'; "
            "doas grep -F \"$nonce\" /var/lib/osmap/audit/helper.log 2>/dev/null | tail -80 || true"
        )
        return self.run_ssh("command_injection_host_evidence.txt", command)

    def write_command_injection_matrix_evidence(
        self,
        nonce: str,
        payloads: list[dict[str, object]],
        surfaces: list[dict[str, object]],
        statuses: dict[str, int | None],
        elapsed: dict[str, float],
        findings: dict[str, list[str]],
    ) -> str:
        lines = [
            "OSMAP-WSTG-INPV-003 command-injection probe matrix:",
            f"nonce={nonce}",
            "safe_payload_classes=shell separators, command substitution syntax, redirects, newlines, percent-encoded variants, double-encoded variants, bounded timing probes, output canaries",
            "destructive_payloads=none",
            f"bounded_timing_sleep_seconds={COMMAND_INJECTION_SLEEP_SECONDS}",
            "",
            "Surfaces:",
        ]
        for surface in surfaces:
            auth = "authenticated" if surface["authenticated"] else "unauthenticated"
            lines.append(f"- {surface['name']}: {auth} {surface['method']} {surface['path']}")
        lines.extend(["", "Payload classes:"])
        for payload in payloads:
            lines.append(f"- {payload['name']}: {payload['class']}")
        lines.extend(["", "Observed statuses and timings:"])
        for label in sorted(statuses):
            lines.append(f"- {label}: status={statuses[label]} elapsed_seconds={elapsed.get(label)}")
        lines.extend(["", "Findings:"])
        if findings:
            for label, probe_findings in sorted(findings.items()):
                lines.append(f"- {label}: {', '.join(probe_findings)}")
        else:
            lines.append("result=passed")
        return self.write_text_evidence("command_injection_probe_matrix.txt", "\n".join(lines) + "\n")

    def write_command_injection_redaction_evidence(self, nonce: str) -> str:
        leaks: dict[str, list[str]] = {}
        forbidden_patterns = [
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
            ("csrf_token_value", r"(?i)csrf_token=(?!\[REDACTED\])[^&\s\"']+"),
            ("csrf_token_field", r'(?i)name=["\']csrf_token["\']\s+value=["\'](?!\[REDACTED\])[^"\']+["\']'),
            ("password_hash", r"\$2[aby]\$[0-9]{2}\$"),
            ("totp_secret", r"(?i)(totp_secret|totp seed|otpauth://|secret=)[A-Z2-7]{16,}"),
            ("authorization_secret", r"(?i)authorization:\s*(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
        ]
        for path in sorted(self.evidence_dir.glob("command_injection_*")):
            if path.name == "command_injection_redaction.txt":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, text)]
            if matches:
                leaks[path.name] = matches
        lines = [
            "Command-injection evidence redaction scan:",
            f"nonce={nonce}",
            "- checked command_injection_* evidence files only",
            "- raw session cookies, CSRF token values, password hashes, TOTP material, and authorization secrets must be absent",
        ]
        if leaks:
            for path, matches in leaks.items():
                lines.append(f"- {path}: {', '.join(matches)}")
        else:
            lines.append("result=passed")
        return self.write_text_evidence("command_injection_redaction.txt", "\n".join(lines) + "\n")

    def test_webmail_input_validation(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-INPV-004", STATUS_SKIP, message)

        canary = f"OSMAP-INPV10-{int(time.time())}-{os.getpid()}"
        self.secrets.append(canary)
        subject_newline = self.form_post(
            "webmail_inpv10_subject_newline",
            "/send",
            {
                "csrf_token": self.csrf_token,
                "to": self.config.test_email,
                "subject": f"{canary}\r\nBcc: injected@example.invalid",
                "body": "subject newline probe",
            },
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
            store_body_evidence=False,
        )
        recipient_newline = self.form_post(
            "webmail_inpv10_recipient_newline",
            "/send",
            {
                "csrf_token": self.csrf_token,
                "to": f"{self.config.test_email}\r\nBcc: injected@example.invalid",
                "subject": f"{canary} recipient newline",
                "body": "recipient newline probe",
            },
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
            store_body_evidence=False,
        )
        display_name = self.form_post(
            "webmail_inpv10_display_name",
            "/send",
            {
                "csrf_token": self.csrf_token,
                "to": f"Injected User <{self.config.test_email}>",
                "subject": f"{canary} display name",
                "body": "display-name probe",
            },
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
            store_body_evidence=False,
        )
        mailbox_tamper = self.request(
            "webmail_inpv10_mailbox_tamper",
            "GET",
            f"/mailbox?name={urllib.parse.quote('INBOX' + chr(13) + chr(10) + 'TAG LOGOUT')}",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        uid_tamper = self.request(
            "webmail_inpv10_uid_tamper",
            "GET",
            "/message?mailbox=INBOX&uid=0",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        search_tamper = self.request(
            "webmail_inpv10_search_tamper",
            "GET",
            f"/search?q={urllib.parse.quote(canary + chr(13) + chr(10) + 'TAG LOGOUT')}",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        attachment_filename = self.multipart_post(
            "webmail_inpv10_attachment_filename",
            "/send",
            {
                "csrf_token": self.csrf_token,
                "to": self.config.test_email,
                "subject": f"{canary} attachment filename",
                "body": "attachment filename probe",
            },
            [("attachment", "../evil.txt", "text/plain", b"safe probe")],
        )
        dangerous_content_type = self.multipart_post(
            "webmail_inpv10_dangerous_content_type",
            "/send",
            {
                "csrf_token": self.csrf_token,
                "to": f"{self.config.test_email}\r\nBcc: injected@example.invalid",
                "subject": f"{canary} dangerous content type",
                "body": "<script>alert(1)</script>",
            },
            [("attachment", "safe.txt", "text/html; charset=utf-8", b"<script>alert(1)</script>")],
        )
        static_ok = self.write_webmail_input_validation_static_evidence()
        redaction_ok = self.write_webmail_input_validation_redaction_evidence([canary])
        statuses = {
            "subject_newline": subject_newline.status,
            "recipient_newline": recipient_newline.status,
            "display_name": display_name.status,
            "mailbox_tamper": mailbox_tamper.status,
            "uid_tamper": uid_tamper.status,
            "search_tamper": search_tamper.status,
            "attachment_filename": attachment_filename.status,
            "dangerous_content_type": dangerous_content_type.status,
        }
        failures: dict[str, object] = {}
        for label in [
            "subject_newline",
            "recipient_newline",
            "display_name",
            "uid_tamper",
            "attachment_filename",
            "dangerous_content_type",
        ]:
            if statuses[label] != 400:
                failures[label] = statuses[label]
        for label in ["mailbox_tamper", "search_tamper"]:
            if statuses[label] not in {400, 404, 503}:
                failures[label] = statuses[label]
        if not static_ok:
            failures["static_boundary"] = "missing webmail input validation markers"
        if not redaction_ok:
            failures["redaction"] = "webmail input validation evidence redaction scan failed"
        evidence_paths = [
            "evidence/webmail_inpv10_subject_newline.headers",
            "evidence/webmail_inpv10_recipient_newline.headers",
            "evidence/webmail_inpv10_display_name.headers",
            "evidence/webmail_inpv10_mailbox_tamper.headers",
            "evidence/webmail_inpv10_uid_tamper.headers",
            "evidence/webmail_inpv10_search_tamper.headers",
            "evidence/webmail_inpv10_attachment_filename.headers",
            "evidence/webmail_inpv10_dangerous_content_type.headers",
            "evidence/webmail_input_validation_static.txt",
            "evidence/webmail_input_validation_redaction.txt",
        ]
        if failures:
            return self.result(
                "OSMAP-WSTG-INPV-004",
                STATUS_FAIL,
                "webmail input validation probes did not meet expected outcomes",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-INPV-004",
            STATUS_PASS,
            "IMAP/SMTP and compose probes rejected header/newline, mailbox, UID, attachment filename, and dangerous content-type inputs",
            evidence_paths,
            {"statuses": statuses},
        )

    def test_http_input_tampering(self) -> TestResult:
        probes = {
            "http_inpv03_options_send": self.request("http_inpv03_options_send", "OPTIONS", "/send"),
            "http_inpv03_put_login": self.request(
                "http_inpv03_put_login",
                "PUT",
                "/login",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="username=probe&password=probe&totp_code=000000",
            ),
            "http_inpv03_get_body_mailboxes": self.request(
                "http_inpv03_get_body_mailboxes",
                "GET",
                "/mailboxes",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="name=INBOX",
            ),
            "http_inpv03_post_mailboxes": self.request(
                "http_inpv03_post_mailboxes",
                "POST",
                "/mailboxes",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="name=INBOX",
            ),
            "http_inpv04_login_json_content_type": self.request(
                "http_inpv04_login_json_content_type",
                "POST",
                "/login",
                headers={"Content-Type": "application/json"},
                body='{"username":"probe","password":"probe","totp_code":"000000"}',
            ),
            "http_inpv04_send_json_content_type": self.request(
                "http_inpv04_send_json_content_type",
                "POST",
                "/send",
                headers={"Content-Type": "application/json", **same_origin_headers(self.config)},
                body='{"to":"probe@example.invalid","subject":"probe","body":"probe"}',
            ),
            "http_inpv04_duplicate_query": self.request(
                "http_inpv04_duplicate_query",
                "GET",
                "/mailbox?name=INBOX&name=Archive",
            ),
            "http_inpv04_duplicate_login_field": self.request(
                "http_inpv04_duplicate_login_field",
                "POST",
                "/login",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body="username=probe&username=admin&password=probe&totp_code=000000",
            ),
            "http_inpv04_duplicate_send_field": self.request(
                "http_inpv04_duplicate_send_field",
                "POST",
                "/send",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    **same_origin_headers(self.config),
                },
                body="csrf_token=one&csrf_token=two&to=probe@example.invalid&subject=probe&body=probe",
            ),
        }
        static_ok = self.write_http_input_tampering_static_evidence()
        failures: dict[str, object] = {}
        for label, evidence in probes.items():
            if evidence.status is None:
                failures[label] = evidence.error or "request failed without HTTP response"
                continue
            if 200 <= evidence.status < 400:
                failures[label] = evidence.status
        if not static_ok:
            failures["static_boundary"] = "missing HTTP input tampering markers"

        evidence_paths = [
            f"evidence/{label}.headers"
            for label in probes
        ] + ["evidence/http_input_tampering_static.txt"]
        statuses = {label: evidence.status for label, evidence in probes.items()}
        if failures:
            return self.result(
                "OSMAP-WSTG-INPV-005",
                STATUS_FAIL,
                "HTTP method, content-type, or duplicate-parameter tampering was accepted",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-INPV-005",
            STATUS_PASS,
            "HTTP method, content-type, and duplicate-parameter tampering probes were rejected",
            evidence_paths,
            {"statuses": statuses},
        )

    def test_http_host_and_smuggling_input(self) -> TestResult:
        host = self.config.host
        evil_host = "evil.example"
        raw_probes = {
            "http_inpv15_cl_te_smuggling": (
                b"POST /login HTTP/1.1\r\n"
                + f"Host: {host}\r\n".encode("ascii")
                + b"Content-Length: 4\r\n"
                + b"Transfer-Encoding: chunked\r\n"
                + b"Connection: close\r\n\r\n"
                + b"0\r\n\r\n"
            ),
            "http_inpv15_duplicate_content_length": (
                b"POST /login HTTP/1.1\r\n"
                + f"Host: {host}\r\n".encode("ascii")
                + b"Content-Length: 0\r\n"
                + b"Content-Length: 5\r\n"
                + b"Connection: close\r\n\r\nabcde"
            ),
            "http_inpv15_encoded_crlf_target": (
                b"GET /login%0d%0aX-Injected:%20yes HTTP/1.1\r\n"
                + f"Host: {host}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            ),
            "http_inpv16_missing_host": b"GET /login HTTP/1.1\r\nConnection: close\r\n\r\n",
            "http_inpv16_folded_header": (
                b"GET /login HTTP/1.1\r\n"
                + f"Host: {host}\r\n".encode("ascii")
                + b"X-OSMAP-WSTG: first\r\n second\r\n"
                + b"Connection: close\r\n\r\n"
            ),
            "http_inpv16_non_normalized_target": (
                b"GET //login HTTP/1.1\r\n"
                + f"Host: {host}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            ),
            "http_inpv17_duplicate_host": (
                b"GET /login HTTP/1.1\r\n"
                + f"Host: {host}\r\n".encode("ascii")
                + f"Host: {evil_host}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            ),
            "http_inpv17_malformed_host": (
                b"GET /login HTTP/1.1\r\n"
                + f"Host: {host}/evil\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            ),
            "http_inpv17_untrusted_host": (
                b"GET /login HTTP/1.1\r\n"
                + f"Host: {evil_host}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            ),
        }
        evidence_by_label = {
            label: self.raw_http_request(label, raw_request)
            for label, raw_request in raw_probes.items()
        }
        static_ok = self.write_http_host_smuggling_static_evidence()
        failures: dict[str, object] = {}
        reject_labels = [
            "http_inpv15_cl_te_smuggling",
            "http_inpv15_duplicate_content_length",
            "http_inpv16_missing_host",
            "http_inpv16_folded_header",
            "http_inpv16_non_normalized_target",
            "http_inpv17_duplicate_host",
            "http_inpv17_malformed_host",
        ]
        for label in reject_labels:
            evidence = evidence_by_label[label]
            if evidence.status != 400:
                failures[label] = evidence.status or evidence.error

        crlf = evidence_by_label["http_inpv15_encoded_crlf_target"]
        crlf_text = "\n".join([crlf.body_text(), "\n".join(f"{k}: {v}" for k, v in crlf.headers)])
        if crlf.status is None or 200 <= crlf.status < 400 or "x-injected" in crlf_text.lower():
            failures["http_inpv15_encoded_crlf_target"] = {
                "status": crlf.status,
                "reflected_injection_marker": "x-injected" in crlf_text.lower(),
            }

        untrusted_host = evidence_by_label["http_inpv17_untrusted_host"]
        untrusted_text = "\n".join(
            [untrusted_host.body_text(), "\n".join(f"{k}: {v}" for k, v in untrusted_host.headers)]
        ).lower()
        if "evil.example" in untrusted_text or untrusted_host.status is None or untrusted_host.status >= 500:
            failures["http_inpv17_untrusted_host"] = {
                "status": untrusted_host.status,
                "reflected_untrusted_host": "evil.example" in untrusted_text,
            }
        if not static_ok:
            failures["static_boundary"] = "missing HTTP host/smuggling markers"

        evidence_paths = [
            f"evidence/{label}.headers"
            for label in raw_probes
        ] + ["evidence/http_host_smuggling_static.txt"]
        statuses = {label: evidence.status for label, evidence in evidence_by_label.items()}
        if failures:
            return self.result(
                "OSMAP-WSTG-INPV-006",
                STATUS_FAIL,
                "HTTP host-header, incoming-request, or smuggling probes did not meet expected outcomes",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-INPV-006",
            STATUS_PASS,
            "HTTP host-header, incoming-request, and splitting/smuggling probes failed closed or avoided host reflection",
            evidence_paths,
            {"statuses": statuses},
        )

    def test_injection_applicability_static(self) -> TestResult:
        banned_dependency_markers = [
            "diesel",
            "rusqlite",
            "sqlx",
            "postgres",
            "mysql",
            "ldap3",
            "quick-xml",
            "roxmltree",
            "sxd-xpath",
            "xpath",
            "tera",
            "handlebars",
            "minijinja",
            "askama",
            "reqwest",
            "ureq",
            "hyper",
        ]
        cargo_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in [REPO_ROOT / "Cargo.toml", REPO_ROOT / "Cargo.lock"]
            if path.exists()
        ).lower()
        source_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted((REPO_ROOT / "src").glob("*.rs"))
        ).lower()
        source_block_markers = [
            "eval(",
            "reqwest::",
            "ureq::",
            "hyper::client",
            "std::process::command",
        ]
        failures: dict[str, object] = {}
        matched_deps = [marker for marker in banned_dependency_markers if re.search(rf'(?m)^name = "{re.escape(marker)}"$|{re.escape(marker)}\s*=', cargo_text)]
        if matched_deps:
            failures["unexpected_dependency_markers"] = matched_deps
        matched_source = [marker for marker in source_block_markers if marker in source_text]
        if matched_source:
            failures["unexpected_source_markers"] = matched_source
        if not self.write_injection_applicability_static_evidence(failures):
            failures["static_boundary"] = "missing injection applicability markers"

        evidence_paths = ["evidence/injection_applicability_static.txt"]
        details = {
            "wstg_not_applicable": [
                "WSTG-v42-INPV-05",
                "WSTG-v42-INPV-06",
                "WSTG-v42-INPV-07",
                "WSTG-v42-INPV-08",
                "WSTG-v42-INPV-09",
                "WSTG-v42-INPV-11",
                "WSTG-v42-INPV-13",
                "WSTG-v42-INPV-14",
                "WSTG-v42-INPV-18",
                "WSTG-v42-INPV-19",
            ],
            "dependency_markers_checked": banned_dependency_markers,
            "source_markers_checked": source_block_markers,
            "failures": failures,
        }
        if failures:
            return self.result(
                "OSMAP-WSTG-INPV-007",
                STATUS_FAIL,
                "remaining Slice 4 injection applicability review found unexpected surfaces",
                evidence_paths,
                details,
            )
        return self.result(
            "OSMAP-WSTG-INPV-007",
            STATUS_PASS,
            "remaining Slice 4 injection classes are not applicable to the current OSMAP browser surface",
            evidence_paths,
            details,
        )

    def write_injection_applicability_static_evidence(self, failures: dict[str, object]) -> bool:
        files = [
            REPO_ROOT / "Cargo.toml",
            REPO_ROOT / "Cargo.lock",
            REPO_ROOT / "src" / "http_form.rs",
            REPO_ROOT / "src" / "http_parse.rs",
            REPO_ROOT / "src" / "rendering.rs",
            REPO_ROOT / "src" / "rendering_html.rs",
            REPO_ROOT / "src" / "send.rs",
            REPO_ROOT / "src" / "mailbox.rs",
            REPO_ROOT / "docs" / "V3_INJECTION_APPLICABILITY_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-INPV-007",
            "WSTG-v42-INPV-05",
            "WSTG-v42-INPV-06",
            "WSTG-v42-INPV-07",
            "WSTG-v42-INPV-08",
            "WSTG-v42-INPV-09",
            "WSTG-v42-INPV-11",
            "WSTG-v42-INPV-13",
            "WSTG-v42-INPV-14",
            "WSTG-v42-INPV-18",
            "WSTG-v42-INPV-19",
            "no SQL database driver",
            "no LDAP client",
            "no XML parser",
            "no XPath engine",
            "no server-side template engine",
            "no outbound HTTP client",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Applicability decisions:",
            "- SQL injection: not applicable; OSMAP has no SQL database driver or query surface.",
            "- LDAP injection: not applicable; OSMAP has no LDAP client or LDAP filter construction surface.",
            "- XML and XPath injection: not applicable; OSMAP has no XML parser, XPath engine, XSLT, SOAP, or XML upload route.",
            "- SSI injection: not applicable; OSMAP has no server-side include interpreter.",
            "- code injection and SSTI: not applicable; OSMAP has no eval, plugin loader, or server-side template engine.",
            "- format-string injection: not applicable to Rust format macros because user input is data arguments, not runtime format strings.",
            "- SSRF: not applicable; OSMAP has no outbound HTTP client or user-controlled URL fetch surface.",
            "- incubated vulnerability: covered for the current surface by the named Slice 4 lanes plus this applicability review.",
        ]
        if failures:
            lines.extend(["", "Unexpected surface markers:", json.dumps(failures, indent=2, sort_keys=True)])
        self.write_text_evidence("injection_applicability_static.txt", "\n".join(lines) + "\n")
        return not missing

    def write_http_host_smuggling_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http_parse.rs",
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "docs" / "V3_HTTP_HOST_SMUGGLING_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "duplicate http header",
            "host header must not be empty",
            "host header contained unsupported characters",
            "http/1.1 requests must include host",
            "unsupported transfer-encoding header",
            "http body length did not match content-length",
            "request target path must be normalized",
            "request target fragments are not supported",
            "OSMAP-WSTG-INPV-006",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "http_host_smuggling_static.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- duplicate Host and Content-Length headers are rejected at the parser or edge boundary\n"
            + "- empty, missing, and malformed Host headers fail closed\n"
            + "- Transfer-Encoding is not accepted by the OSMAP parser and CL.TE probes fail at the public edge\n"
            + "- non-normalized request targets and encoded CRLF target probes do not reach successful browser routes\n"
            + "- the application uses relative redirects and does not derive trusted URLs from arbitrary Host input\n",
        )
        return not missing

    def write_http_input_tampering_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http_parse.rs",
            REPO_ROOT / "src" / "http_form.rs",
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "src" / "http" / "routes_auth.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "docs" / "V3_HTTP_INPUT_TAMPERING_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "unsupported http method",
            "get requests must not send a request body",
            "post requests must send content-length",
            "allows_urlencoded_request_body",
            "unsupported compose content-type",
            "duplicate form field",
            "duplicate query fields must be rejected",
            "OSMAP-WSTG-INPV-005",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "http_input_tampering_static.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- the HTTP parser admits only GET and POST and rejects unsupported verbs before routing\n"
            + "- GET requests with bodies and malformed POST bodies fail at the parser boundary\n"
            + "- form routes accept URL-encoded bodies only, except compose/draft routes that also accept bounded multipart form-data\n"
            + "- URL query, URL-encoded body, and multipart field parsers reject duplicate field names\n"
            + "- method mismatches on browser routes do not create alternate state-changing entry points\n",
        )
        return not missing

    def multipart_post(
        self,
        label: str,
        path: str,
        fields: dict[str, str],
        files: list[tuple[str, str, str, bytes]],
    ) -> HttpEvidence:
        boundary = "osmap-wstg-multipart"
        return self.request(
            label,
            "POST",
            path,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                **same_origin_headers(self.config),
            },
            body=build_multipart_form(boundary, fields, files),
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )

    def write_webmail_input_validation_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "send.rs",
            REPO_ROOT / "src" / "http_form.rs",
            REPO_ROOT / "src" / "attachment.rs",
            REPO_ROOT / "src" / "mailbox.rs",
            REPO_ROOT / "src" / "rendering_html.rs",
            REPO_ROOT / "docs" / "V3_WEBMAIL_INPUT_VALIDATION_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "recipient contained control or whitespace characters",
            "subject must not contain line breaks",
            "attachment filename contained control characters",
            "attachment filename must not contain path separators",
            "normalize_attachment_content_type",
            "application/octet-stream",
            "rejects_attachment_filenames_with_path_separators",
            "rejects_subject_line_breaks",
            "sendmail_backend_keeps_shell_shaped_sender_as_one_arg_and_body_on_stdin",
            "doveadm_search_keeps_shell_shaped_query_as_one_argument",
            "strips_scriptable_attributes_forms_remote_fetch_surfaces_and_comments",
            "OSMAP-WSTG-INPV-004",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "webmail_input_validation_static.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- recipient, display-name-shaped recipient, and subject header injection are rejected before submission\n"
            + "- body text may contain ordinary line breaks but remains stdin data, not command arguments\n"
            + "- attachment filenames reject control characters and path separators\n"
            + "- unsafe attachment content types normalize to application/octet-stream\n"
            + "- mailbox/search command-shaped values remain argument-bounded at the Dovecot boundary\n"
            + "- stored HTML rendering strips active content and remote-fetch surfaces\n",
        )
        return not missing

    def write_webmail_input_validation_redaction_evidence(self, forbidden_values: list[str]) -> bool:
        leaks: dict[str, list[str]] = {}
        forbidden_patterns = [
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
            ("csrf_token_value", r"(?i)csrf_token=[^&\s\"']+"),
        ]
        for value in forbidden_values:
            if value:
                forbidden_patterns.append((f"value_{len(forbidden_patterns)}", re.escape(value)))
        paths = sorted(self.evidence_dir.glob("webmail_inpv10_*")) + sorted(self.evidence_dir.glob("webmail_input_validation_*"))
        for path in paths:
            if path.name == "webmail_input_validation_redaction.txt":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, text)]
            if matches:
                leaks[path.name] = matches
        lines = [
            "Webmail input validation evidence redaction scan:",
            "- checked webmail_inpv10_* and webmail_input_validation_* evidence files only",
            "- raw session cookies, CSRF token values, and generated canaries must be absent",
        ]
        if leaks:
            lines.append("Leaks detected:")
            for path, matches in leaks.items():
                lines.append(f"- {path}: {', '.join(matches)}")
        else:
            lines.append("result=passed")
        self.write_text_evidence("webmail_input_validation_redaction.txt", "\n".join(lines) + "\n")
        return not leaks

    def test_cors(self) -> TestResult:
        bad: dict[str, dict[str, str]] = {}
        evidence_paths: list[str] = []
        probes = [
            ("GET", "/login", {}),
            ("GET", "/mailboxes", {}),
            ("OPTIONS", "/login", {"Access-Control-Request-Method": "POST"}),
            ("OPTIONS", "/messages/move", {"Access-Control-Request-Method": "POST"}),
            ("OPTIONS", "/send", {"Access-Control-Request-Method": "POST"}),
        ]
        for origin in ["https://attacker.invalid", "null"]:
            for method, path, extra_headers in probes:
                label = f"cors_{method.lower()}_{safe_label(path)}_{origin.replace(':', '_').replace('/', '_')}"
                headers = {"Origin": origin}
                headers.update(extra_headers)
                evidence = self.request(label, method, path, headers=headers)
                evidence_paths.append(f"evidence/{safe_label(label)}.headers")
                acao = evidence.first_header("Access-Control-Allow-Origin")
                acac = evidence.first_header("Access-Control-Allow-Credentials")
                if acac.lower() == "true" and acao in {origin, "*"}:
                    bad[f"{method} {path} {origin}"] = {"acao": acao, "acac": acac}
        if bad:
            return self.result("OSMAP-WSTG-CLNT-001", STATUS_FAIL, "credentialed cross-origin CORS was allowed", evidence_paths, {"bad": bad})
        return self.result("OSMAP-WSTG-CLNT-001", STATUS_PASS, "cross-origin simple and preflight probes did not receive permissive credentialed CORS", evidence_paths)

    def write_html_rendering_static_boundary_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "rendering.rs",
            REPO_ROOT / "src" / "rendering_html.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "docs" / "RENDERING_POLICY_BASELINE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = ["sanitize", "escape_html", "default-src 'none'", "external", "script"]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence("static_html_rendering.txt", summarize_static_files(files, missing))
        return not missing

    def test_client_side_applicability_static(self) -> TestResult:
        source_files = list(sorted((REPO_ROOT / "src").glob("*.rs"))) + [REPO_ROOT / "Cargo.toml", REPO_ROOT / "Cargo.lock"]
        source_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in source_files if path.exists()).lower()
        absent_markers = ["localstorage", "sessionstorage", "websocket", "postmessage", "serviceworker", "indexeddb", "swf"]
        matched = [marker for marker in absent_markers if marker in source_text]
        static_ok = self.write_client_side_applicability_static_evidence(matched)
        evidence = ["evidence/client_side_applicability_static.txt"]
        if matched or not static_ok:
            return self.result("OSMAP-WSTG-CLNT-003", STATUS_FAIL, "client-side/browser-storage applicability review found unexpected source markers", evidence, {"unexpected_markers": matched})
        return self.result("OSMAP-WSTG-CLNT-003", STATUS_PASS, "remaining client-side and browser-storage rows are covered or not applicable to the current server-rendered surface", evidence, {"absent_markers_checked": absent_markers})

    def write_client_side_applicability_static_evidence(self, matched: list[str]) -> bool:
        files = [
            REPO_ROOT / "Cargo.toml",
            REPO_ROOT / "Cargo.lock",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "src" / "http_ui.rs",
            REPO_ROOT / "src" / "rendering_html.rs",
            REPO_ROOT / "src" / "rendering.rs",
            REPO_ROOT / "docs" / "HTTP_HARDENING_BASELINE.md",
            REPO_ROOT / "docs" / "RENDERING_POLICY_BASELINE.md",
            REPO_ROOT / "docs" / "V3_CLIENT_SIDE_BROWSER_SECURITY.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-CLNT-003",
            "WSTG-v42-CLNT-02",
            "WSTG-v42-CLNT-03",
            "WSTG-v42-CLNT-04",
            "WSTG-v42-CLNT-05",
            "WSTG-v42-CLNT-06",
            "WSTG-v42-CLNT-08",
            "WSTG-v42-CLNT-10",
            "WSTG-v42-CLNT-11",
            "WSTG-v42-CLNT-12",
            "WSTG-v42-CLNT-13",
            "default-src 'none'",
            "frame-ancestors 'none'",
            "no client-side scripting dependency",
            "UrlRelative::Deny",
            "noopener noreferrer nofollow",
            "no WebSocket route",
            "no browser storage use",
            "no web messaging surface",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Applicability decisions:",
            "- JavaScript execution, client-side redirects, resource manipulation, web messaging, browser storage, and XSSI are not applicable to the current server-rendered surface because OSMAP has no client-side scripting dependency.",
            "- HTML and CSS injection are covered by the sanitizer, escaping, default-deny CSP, stripped scriptable tags, denied relative URLs, and stripped remote-fetch surfaces.",
            "- Cross Site Flashing, WebSockets, and browser storage are not applicable: OSMAP has no Flash/SWF, no WebSocket route, and no browser storage use.",
            "- Reverse-tabnabbing and cross-site script inclusion are constrained by rel=\"noopener noreferrer nofollow\" links and default-src 'none'.",
        ]
        if matched:
            lines.extend(["", "Unexpected client-side markers:", json.dumps(matched, indent=2)])
        self.write_text_evidence("client_side_applicability_static.txt", "\n".join(lines) + "\n")
        return not missing

    def write_attachment_static_boundary_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http_form.rs",
            REPO_ROOT / "src" / "attachment.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "docs" / "MIME_AND_ATTACHMENT_POLICY_BASELINE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = ["multipart", "max_upload_body", "Content-Disposition", "attachment", "nosniff", "no-store"]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence("static_attachment_handling.txt", summarize_static_files(files, missing))
        return not missing

    def mime_html_live_evidence(self) -> str:
        if self.mime_html_live_report is not None:
            return self.mime_html_live_report
        remote_repo = os.environ.get("OSMAP_WSTG_REMOTE_REPO", "/home/foo/OSMAP")
        expected_ref = os.environ.get("OSMAP_WSTG_EXPECTED_REF", local_git_head())
        self.mime_html_live_report = self.run_ssh(
            "mime_html_live_report.txt",
            "set -eu; "
            f"cd {shlex.quote(remote_repo)}; "
            "remote_ref=$(git rev-parse HEAD); "
            f"expected_ref={shlex.quote(expected_ref)}; "
            "if [ \"$remote_ref\" != \"$expected_ref\" ]; then "
            "printf 'ERROR: remote repo ref mismatch expected=%s actual=%s\\n' \"$expected_ref\" \"$remote_ref\"; exit 1; "
            "fi; "
            "ksh ./maint/live/osmap-live-validate-v3-mime-html-proof.ksh >/tmp/osmap-wstg-mime-html-live.log 2>&1 || { cat /tmp/osmap-wstg-mime-html-live.log; exit 1; }; "
            "cat ./maint/live/latest-host-v3-mime-html-proof-report.txt; printf '\\n--- validator log ---\\n'; cat /tmp/osmap-wstg-mime-html-live.log",
        )
        return self.mime_html_live_report

    def test_html_rendering_live(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-CLNT-002", STATUS_SKIP, "host-assisted live HTML rendering evidence disabled")
        static_ok = self.write_html_rendering_static_boundary_evidence()
        live = self.mime_html_live_evidence()
        evidence_paths = ["evidence/mime_html_live_report.txt", "evidence/static_html_rendering.txt"]
        required = [
            "result=v3_mime_html_live_proof_passed",
            "sanitized_html_mode=present",
            "sanitized_html_javascript_scheme=absent",
            "sanitized_html_data_scheme=absent",
            "sanitized_html_remote_payload=absent",
            "sanitized_html_body_marker_audit_leakage=absent",
        ]
        missing = [marker for marker in required if marker not in live]
        failures: dict[str, object] = {}
        if "ERROR:" in live:
            failures["ssh"] = "host-assisted MIME/HTML validator was unavailable or ran against the wrong ref"
        if not static_ok:
            failures["static_boundary"] = "missing HTML rendering boundary markers"
        if missing:
            failures["missing_live_markers"] = missing
        if failures:
            return self.result("OSMAP-WSTG-CLNT-002", STATUS_FAIL, "live HTML rendering WSTG evidence did not meet expected outcomes", evidence_paths, failures)
        return self.result("OSMAP-WSTG-CLNT-002", STATUS_PASS, "host-backed HTML sanitization and unsafe-content rejection evidence passed", evidence_paths)

    def test_attachment_live(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-BUSL-001", STATUS_SKIP, "host-assisted live attachment evidence disabled")
        static_ok = self.write_attachment_static_boundary_evidence()
        live = self.mime_html_live_evidence()
        evidence_paths = ["evidence/mime_html_live_report.txt", "evidence/static_attachment_handling.txt"]
        required = [
            "result=v3_mime_html_live_proof_passed",
            "inline_image_attachment_download_status=HTTP/1.1 200 OK",
            "delivery_status_attachment_download_status=HTTP/1.1 200 OK",
            "original_message_attachment_download_status=HTTP/1.1 200 OK",
            "inline_image_body_marker_audit_leakage=absent",
            "delivery_status_body_marker_audit_leakage=absent",
            "original_message_body_marker_audit_leakage=absent",
        ]
        missing = [marker for marker in required if marker not in live]
        failures: dict[str, object] = {}
        if "ERROR:" in live:
            failures["ssh"] = "host-assisted MIME/HTML validator was unavailable or ran against the wrong ref"
        if not static_ok:
            failures["static_boundary"] = "missing attachment handling boundary markers"
        if missing:
            failures["missing_live_markers"] = missing
        if failures:
            return self.result("OSMAP-WSTG-BUSL-001", STATUS_FAIL, "live attachment WSTG evidence did not meet expected outcomes", evidence_paths, failures)
        return self.result("OSMAP-WSTG-BUSL-001", STATUS_PASS, "host-backed attachment download, forced-download, and redaction evidence passed", evidence_paths)

    def write_bulk_folder_actions_static_boundary_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http_runtime.rs",
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "src" / "http_ui.rs",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "docs" / "V3_ACCEPTANCE_CRITERIA.md",
            REPO_ROOT / "docs" / "V3_SECURITY_GATES.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            '"/messages/move"',
            "bulk_message_move",
            "bulk_message_archive",
            "MAX_BULK_ARCHIVE_MESSAGES",
            "bulk_move_destination_allowed",
            "require_valid_csrf",
            "bulk_move_rejects_unapproved_destination_before_moving",
            "bulk_move_reports_partial_success_when_later_uid_is_stale",
        ]
        missing = [marker for marker in markers if marker not in text]
        self.write_text_evidence("static_bulk_folder_actions.txt", summarize_static_files(files, missing))
        return not missing

    def test_bulk_folder_actions_live(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-BUSL-004", STATUS_SKIP, "host-assisted live bulk folder-action evidence disabled")
        evidence_paths = [
            "evidence/bulk_folder_actions_live_report.txt",
            "evidence/static_bulk_folder_actions.txt",
        ]
        static_ok = self.write_bulk_folder_actions_static_boundary_evidence()
        remote_repo = os.environ.get("OSMAP_WSTG_REMOTE_REPO", "/home/foo/OSMAP")
        expected_ref = os.environ.get("OSMAP_WSTG_EXPECTED_REF", local_git_head())
        live = self.run_ssh(
            "bulk_folder_actions_live_report.txt",
            "set -eu; "
            f"cd {shlex.quote(remote_repo)}; "
            "remote_ref=$(git rev-parse HEAD); "
            f"expected_ref={shlex.quote(expected_ref)}; "
            "if [ \"$remote_ref\" != \"$expected_ref\" ]; then "
            "printf 'ERROR: remote repo ref mismatch expected=%s actual=%s\\n' \"$expected_ref\" \"$remote_ref\"; exit 1; "
            "fi; "
            "ksh ./maint/live/osmap-live-validate-archive-shortcut.ksh >/tmp/osmap-wstg-busl-004-live.log 2>&1 || { cat /tmp/osmap-wstg-busl-004-live.log; exit 1; }; "
            "cat /tmp/osmap-wstg-busl-004-live.log",
        )
        required_markers = [
            "live archive shortcut validation passed",
            "settings_status=HTTP/1.1 303 See Other",
            "move_status=HTTP/1.1 303 See Other",
            "selected_archive_status=HTTP/1.1 303 See Other",
            "mailbox page did not render selected archive form",
        ]
        forbidden_markers = [marker for marker in required_markers if marker.startswith("mailbox page did not")]
        required_markers = [marker for marker in required_markers if marker not in forbidden_markers]
        missing = [marker for marker in required_markers if marker not in live]
        failures: dict[str, object] = {}
        if "ERROR:" in live:
            failures["ssh"] = "host-assisted live validator was unavailable or ran against the wrong ref"
        if not static_ok:
            failures["static_boundary"] = "missing bulk folder-action route markers"
        if missing:
            failures["missing_live_markers"] = missing
        if any(marker in live for marker in forbidden_markers):
            failures["unexpected_live_failures"] = forbidden_markers
        if failures:
            return self.result(
                "OSMAP-WSTG-BUSL-004",
                STATUS_FAIL,
                "bounded bulk folder-action WSTG evidence did not meet expected outcomes",
                evidence_paths,
                failures,
            )
        return self.result(
            "OSMAP-WSTG-BUSL-004",
            STATUS_PASS,
            "host-backed selected archive and bulk folder-action controls passed live request/response validation",
            evidence_paths,
        )

    def test_authorization_account_isolation(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-ATHZ-001", STATUS_SKIP, message)
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-ATHZ-001", STATUS_SKIP, "host-assisted account-isolation evidence disabled")
        if not self.config.secondary_email:
            return self.result("OSMAP-WSTG-ATHZ-001", STATUS_SKIP, "OSMAP_SECONDARY_EMAIL is required for account-isolation evidence")

        token = f"osmap-athz-{int(time.time())}-{os.getpid()}"
        inbox_subject = f"OSMAP ATHZ isolation inbox {token}"
        sent_subject = f"OSMAP ATHZ isolation sent {token}"
        attachment_marker = f"OSMAP ATHZ attachment marker {token}"
        self.secrets.extend([token, inbox_subject, sent_subject, attachment_marker])

        remote_report = self.provision_secondary_authorization_fixture(
            inbox_subject,
            sent_subject,
            attachment_marker,
        )
        fields = {}
        for line in remote_report.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key.strip()] = value.strip()

        evidence_paths = [
            "evidence/authorization_account_isolation_fixture.txt",
            "evidence/authz_cross_user_mailbox_tamper.headers",
            "evidence/authz_cross_user_message.headers",
            "evidence/authz_cross_user_attachment.headers",
            "evidence/authz_cross_user_sent.headers",
            "evidence/authz_cross_user_search.headers",
            "evidence/authz_route_bypass_no_cookie.headers",
            "evidence/authz_route_bypass_stale_cookie.headers",
            "evidence/authorization_account_isolation_cleanup.txt",
            "evidence/authorization_account_isolation_static.txt",
            "evidence/authorization_account_isolation_redaction.txt",
        ]
        inbox_uid = fields.get("secondary_inbox_uid", "1")
        sent_uid = fields.get("secondary_sent_uid", "1")
        mailbox_tamper = self.request(
            "authz_cross_user_mailbox_tamper",
            "GET",
            "/mailbox?name=NotARealMailbox",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        message_probe = self.request(
            "authz_cross_user_message",
            "GET",
            f"/message?mailbox=INBOX&uid={urllib.parse.quote(inbox_uid)}",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        attachment_probe = self.request(
            "authz_cross_user_attachment",
            "GET",
            f"/attachment?mailbox=INBOX&uid={urllib.parse.quote(inbox_uid)}&part=1.2",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        sent_probe = self.request(
            "authz_cross_user_sent",
            "GET",
            f"/message?mailbox=Sent&uid={urllib.parse.quote(sent_uid)}",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        search_probe = self.request(
            "authz_cross_user_search",
            "GET",
            f"/search?q={urllib.parse.quote(token)}&scope=all",
            cookies=self.cookie_jar,
            store_body_evidence=False,
        )
        no_cookie = self.request("authz_route_bypass_no_cookie", "GET", "/mailboxes", store_body_evidence=False)
        stale_cookie = self.request(
            "authz_route_bypass_stale_cookie",
            "GET",
            "/mailboxes",
            cookies={"osmap_session": "f" * 64},
            store_body_evidence=False,
        )
        self.cleanup_secondary_authorization_fixture(inbox_subject, sent_subject)

        static_ok = self.write_authorization_account_isolation_static_evidence()
        redaction_ok = self.write_authorization_account_isolation_redaction_evidence(
            [token, inbox_subject, sent_subject, attachment_marker],
        )
        forbidden_exposure = {
            "message_subject": inbox_subject in message_probe.body_text(),
            "attachment_marker": attachment_marker in attachment_probe.body_text(),
            "sent_subject": sent_subject in sent_probe.body_text(),
            "search_subject": token in search_probe.body_text(),
        }
        statuses = {
            "mailbox_tamper": mailbox_tamper.status,
            "message_probe": message_probe.status,
            "attachment_probe": attachment_probe.status,
            "sent_probe": sent_probe.status,
            "search_probe": search_probe.status,
            "no_cookie": no_cookie.status,
            "stale_cookie": stale_cookie.status,
        }
        failures: dict[str, object] = {}
        missing_fields = [field for field in ["secondary_inbox_uid", "secondary_sent_uid", "fixture_result"] if not fields.get(field)]
        if "ERROR:" in remote_report or fields.get("fixture_result") != "prepared":
            failures["fixture"] = "secondary fixture was not prepared"
        if missing_fields:
            failures["missing_fixture_fields"] = missing_fields
        if mailbox_tamper.status not in {400, 404, 503}:
            failures["mailbox_tamper_status"] = mailbox_tamper.status
        if no_cookie.status == 200 or stale_cookie.status == 200:
            failures["route_authorization_bypass"] = statuses
        exposed = [name for name, exposed in forbidden_exposure.items() if exposed]
        if exposed:
            failures["cross_user_exposure"] = exposed
        if not static_ok:
            failures["static_boundary"] = "missing authorization boundary markers"
        if not redaction_ok:
            failures["redaction"] = "authorization evidence redaction scan failed"
        if failures:
            return self.result(
                "OSMAP-WSTG-ATHZ-001",
                STATUS_FAIL,
                "authorization account-isolation evidence did not meet expected outcomes",
                evidence_paths,
                {"statuses": statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-ATHZ-001",
            STATUS_PASS,
            "primary session could not expose secondary mailbox, message, attachment, sent, search, stale-session, or route-bypass evidence",
            evidence_paths,
            {"statuses": statuses},
        )

    def provision_secondary_authorization_fixture(
        self,
        inbox_subject: str,
        sent_subject: str,
        attachment_marker: str,
    ) -> str:
        command = f"""
set -eu
secondary={shlex.quote(self.config.secondary_email)}
inbox_subject={shlex.quote(inbox_subject)}
sent_subject={shlex.quote(sent_subject)}
attachment_marker={shlex.quote(attachment_marker)}
doveadm='/usr/local/bin/doveadm -o stats_writer_socket_path='
doas -u vmail $doveadm mailbox list -u "$secondary" | grep -Fxq INBOX
doas -u vmail $doveadm mailbox list -u "$secondary" | grep -Fxq Sent
{{
  printf 'From: OSMAP ATHZ Proof <%s>\\n' "$secondary"
  printf 'To: %s\\n' "$secondary"
  printf 'Subject: %s\\n' "$inbox_subject"
  printf 'MIME-Version: 1.0\\n'
  printf 'Content-Type: multipart/mixed; boundary="osmap-athz-boundary"\\n'
  printf '\\n--osmap-athz-boundary\\n'
  printf 'Content-Type: text/plain; charset=utf-8\\n\\n'
  printf 'secondary account isolation proof body\\n'
  printf '\\n--osmap-athz-boundary\\n'
  printf 'Content-Type: text/plain; name="athz-proof.txt"\\n'
  printf 'Content-Disposition: attachment; filename="athz-proof.txt"\\n\\n'
  printf '%s\\n' "$attachment_marker"
  printf '\\n--osmap-athz-boundary--\\n'
}} | /usr/sbin/sendmail -t
{{
  printf 'From: OSMAP ATHZ Proof <%s>\\n' "$secondary"
  printf 'To: %s\\n' "$secondary"
  printf 'Subject: %s\\n' "$sent_subject"
  printf 'Content-Type: text/plain; charset=utf-8\\n\\n'
  printf 'secondary sent isolation proof body\\n'
}} | /usr/sbin/sendmail -t
lookup_uid() {{
  mailbox=$1
  subject=$2
  doas -u vmail $doveadm search -u "$secondary" mailbox "$mailbox" header Subject "$subject" | awk 'NF > 0 {{ print $NF; exit }}'
}}
inbox_uid=''
sent_uid=''
tries=0
while {{ [ -z "$inbox_uid" ] || [ -z "$sent_uid" ]; }} && [ "$tries" -lt 30 ]; do
  [ -n "$inbox_uid" ] || inbox_uid=$(lookup_uid INBOX "$inbox_subject" || true)
  [ -n "$sent_uid" ] || sent_uid=$(lookup_uid INBOX "$sent_subject" || true)
  [ -n "$inbox_uid" ] && [ -n "$sent_uid" ] && break
  sleep 1
  tries=$((tries + 1))
done
[ -n "$inbox_uid" ]
[ -n "$sent_uid" ]
doas -u vmail $doveadm move -u "$secondary" Sent mailbox INBOX uid "$sent_uid" >/dev/null
sent_uid_after=''
tries=0
while [ -z "$sent_uid_after" ] && [ "$tries" -lt 20 ]; do
  sent_uid_after=$(lookup_uid Sent "$sent_subject" || true)
  [ -n "$sent_uid_after" ] && break
  sleep 1
  tries=$((tries + 1))
done
[ -n "$sent_uid_after" ]
printf 'fixture_result=prepared\\n'
printf 'secondary_mailboxes=INBOX,Sent\\n'
printf 'secondary_inbox_uid=%s\\n' "$inbox_uid"
printf 'secondary_sent_uid=%s\\n' "$sent_uid_after"
printf 'secret_review=No password, password hash, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.\\n'
"""
        return self.run_ssh("authorization_account_isolation_fixture.txt", command)

    def cleanup_secondary_authorization_fixture(self, inbox_subject: str, sent_subject: str) -> None:
        command = (
            "set -u; "
            f"secondary={shlex.quote(self.config.secondary_email)}; "
            f"inbox_subject={shlex.quote(inbox_subject)}; "
            f"sent_subject={shlex.quote(sent_subject)}; "
            "doveadm='/usr/local/bin/doveadm -o stats_writer_socket_path='; "
            'doas -u vmail $doveadm expunge -u "$secondary" mailbox INBOX header Subject "$inbox_subject" >/dev/null 2>&1 || true; '
            'doas -u vmail $doveadm expunge -u "$secondary" mailbox INBOX header Subject "$sent_subject" >/dev/null 2>&1 || true; '
            'doas -u vmail $doveadm expunge -u "$secondary" mailbox Sent header Subject "$sent_subject" >/dev/null 2>&1 || true; '
            "printf 'cleanup_result=attempted\\n'"
        )
        self.run_ssh("authorization_account_isolation_cleanup.txt", command)

    def write_authorization_account_isolation_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http_gateway_mail.rs",
            REPO_ROOT / "src" / "http_gateway_draft.rs",
            REPO_ROOT / "src" / "draft.rs",
            REPO_ROOT / "src" / "mailbox_helper_protocol.rs",
            REPO_ROOT / "docs" / "V3_AUTHORIZATION_ACCOUNT_ISOLATION.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "validated_session.record.canonical_username",
            "list_for_validated_session",
            "fetch_for_validated_session",
            "download_for_validated_session",
            "submit_for_validated_session",
            "delete_draft",
            "file_draft_store_scopes_loads_by_owner",
            "message_search_mailbox_rejected",
            "MessageMoveThrottleKey::for_canonical_user_and_remote_addr",
            "grant canonical_username",
            "OSMAP-WSTG-ATHZ-001",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "authorization_account_isolation_static.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- browser routes derive mailbox, message, attachment, draft, send, search, and bulk-action authority from the validated session\n"
            + "- mailbox helper grants bind canonical username to mailbox, UID, part, and mutation operation fields\n"
            + "- secondary account fixture probes are redacted and assert marker absence through the primary session\n"
            + "- draft ownership isolation is covered by owner-hashed storage and cross-owner load tests\n",
        )
        return not missing

    def write_authorization_account_isolation_redaction_evidence(self, forbidden_values: list[str]) -> bool:
        leaks: dict[str, list[str]] = {}
        forbidden_patterns = [
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
            ("csrf_token_value", r"(?i)csrf_token=[A-Za-z0-9._~+/=-]{16,}"),
            ("password_hash", r"\$2[aby]\$[0-9]{2}\$"),
            ("totp_secret", r"(?i)(totp|secret)[_=][A-Z2-7]{16,}"),
        ]
        for value in forbidden_values:
            if value:
                forbidden_patterns.append((f"value_{len(forbidden_patterns)}", re.escape(value)))
        paths = sorted(self.evidence_dir.glob("authz_*")) + sorted(self.evidence_dir.glob("authorization_account_isolation_*"))
        for path in paths:
            if path.name == "authorization_account_isolation_redaction.txt":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, text)]
            if matches:
                leaks[path.name] = matches
        lines = [
            "Authorization account-isolation evidence redaction scan:",
            "- checked authz_* and authorization_account_isolation_* evidence files only",
            "- raw session cookies, CSRF token values, password hashes, TOTP material, fixture subjects, and attachment markers must be absent",
        ]
        if leaks:
            lines.append("Leaks detected:")
            for path, matches in leaks.items():
                lines.append(f"- {path}: {', '.join(matches)}")
        else:
            lines.append("result=passed")
        self.write_text_evidence("authorization_account_isolation_redaction.txt", "\n".join(lines) + "\n")
        return not leaks

    def test_draft_routes_authenticated(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-BUSL-002", STATUS_SKIP, message)

        nonce = hashlib.sha256(f"{time.time()}:{os.getpid()}".encode("utf-8")).hexdigest()[:12]
        subject = f"OSMAP WSTG draft route proof {nonce}"
        body = f"OSMAP WSTG draft body proof {nonce}"
        delete_subject = f"OSMAP WSTG draft delete proof {nonce}"
        delete_body = f"OSMAP WSTG draft delete body {nonce}"
        for value in [subject, body, delete_subject, delete_body, nonce]:
            self.secrets.append(value)

        evidence_paths = [
            "evidence/draft_save_missing_csrf.headers",
            "evidence/draft_save_cross_origin.headers",
            "evidence/draft_save_attachment_limit.headers",
            "evidence/draft_delete_create.headers",
            "evidence/draft_delete.headers",
            "evidence/draft_delete_resume.headers",
            "evidence/draft_send_create.headers",
            "evidence/draft_list_before_send.headers",
            "evidence/draft_list_before_send.body",
            "evidence/draft_resume_before_send.headers",
            "evidence/draft_resume_before_send.body",
            "evidence/draft_send_cleanup.headers",
            "evidence/draft_send_resume_after_cleanup.headers",
            "evidence/draft_stale_session_rejected.headers",
            "evidence/draft_route_static_boundary.txt",
            "evidence/draft_route_evidence_redaction.txt",
        ]

        missing = self.form_post(
            "draft_save_missing_csrf",
            "/drafts/save",
            {"to": self.config.test_email, "subject": subject, "body": body},
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
        )
        cross = self.form_post(
            "draft_save_cross_origin",
            "/drafts/save",
            {
                "csrf_token": self.csrf_token,
                "to": self.config.test_email,
                "subject": subject,
                "body": body,
            },
            cookies=self.cookie_jar,
            headers={"Origin": "https://attacker.invalid"},
        )
        attachment_limit = self.request(
            "draft_save_attachment_limit",
            "POST",
            "/drafts/save",
            headers={
                "Content-Type": "multipart/form-data; boundary=osmap-wstg-draft-limit",
                **same_origin_headers(self.config),
            },
            body=build_multipart_form(
                "osmap-wstg-draft-limit",
                {
                    "csrf_token": self.csrf_token,
                    "to": self.config.test_email,
                    "subject": subject,
                    "body": body,
                },
                [
                    ("attachment", f"limit-{index}.txt", "text/plain", b"x")
                    for index in range(4)
                ],
            ),
            cookies=self.cookie_jar,
        )

        delete_create = self.form_post(
            "draft_delete_create",
            "/drafts/save",
            {
                "csrf_token": self.csrf_token,
                "to": self.config.test_email,
                "subject": delete_subject,
                "body": delete_body,
            },
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
        )
        delete_draft_id = draft_id_from_location(delete_create.first_header("Location"))
        delete: HttpEvidence | None = None
        delete_resume: HttpEvidence | None = None
        if delete_draft_id:
            delete = self.form_post(
                "draft_delete",
                "/drafts/delete",
                {"csrf_token": self.csrf_token, "draft_id": delete_draft_id},
                cookies=self.cookie_jar,
                headers=same_origin_headers(self.config),
            )
            delete_resume = self.request(
                "draft_delete_resume",
                "GET",
                f"/draft?id={urllib.parse.quote(delete_draft_id)}",
                cookies=self.cookie_jar,
                store_body_evidence=False,
            )

        send_create = self.form_post(
            "draft_send_create",
            "/drafts/save",
            {
                "csrf_token": self.csrf_token,
                "to": self.config.test_email,
                "subject": subject,
                "body": body,
            },
            cookies=self.cookie_jar,
            headers=same_origin_headers(self.config),
        )
        send_draft_id = draft_id_from_location(send_create.first_header("Location"))
        draft_list = self.request("draft_list_before_send", "GET", "/drafts", cookies=self.cookie_jar)
        draft_resume: HttpEvidence | None = None
        send: HttpEvidence | None = None
        send_resume: HttpEvidence | None = None
        if send_draft_id:
            draft_resume = self.request(
                "draft_resume_before_send",
                "GET",
                f"/draft?id={urllib.parse.quote(send_draft_id)}",
                cookies=self.cookie_jar,
                store_body_evidence=False,
            )
            send = self.form_post(
                "draft_send_cleanup",
                "/send",
                {
                    "csrf_token": self.csrf_token,
                    "draft_id": send_draft_id,
                    "to": self.config.test_email,
                    "subject": subject,
                    "body": body,
                },
                cookies=self.cookie_jar,
                headers=same_origin_headers(self.config),
                store_body_evidence=False,
            )
            send_resume = self.request(
                "draft_send_resume_after_cleanup",
                "GET",
                f"/draft?id={urllib.parse.quote(send_draft_id)}",
                cookies=self.cookie_jar,
                store_body_evidence=False,
            )
        stale = self.request(
            "draft_stale_session_rejected",
            "GET",
            "/drafts",
            cookies={"osmap_session": "e" * 64},
            store_body_evidence=False,
        )

        static_evidence = self.write_draft_static_boundary_evidence()
        redaction_evidence = self.write_draft_evidence_redaction_evidence(
            [subject, body, delete_subject, delete_body, nonce, self.csrf_token],
        )

        expected_statuses = {
            "missing_csrf": missing.status,
            "cross_origin": cross.status,
            "attachment_limit": attachment_limit.status,
            "delete_create": delete_create.status,
            "delete": status_of(delete),
            "delete_resume": status_of(delete_resume),
            "send_create": send_create.status,
            "list": draft_list.status,
            "resume": status_of(draft_resume),
            "send": status_of(send),
            "send_resume": status_of(send_resume),
            "stale_session": stale.status,
        }
        failures: dict[str, int | None] = {}
        if missing.status != 403:
            failures["missing_csrf"] = missing.status
        if cross.status != 403:
            failures["cross_origin"] = cross.status
        if attachment_limit.status not in {400, 413}:
            failures["attachment_limit"] = attachment_limit.status
        if delete_create.status != 303 or not delete_draft_id:
            failures["delete_create"] = delete_create.status
        if delete_draft_id and status_of(delete) != 303:
            failures["delete"] = status_of(delete)
        if delete_draft_id and status_of(delete_resume) != 404:
            failures["delete_resume"] = status_of(delete_resume)
        if send_create.status != 303 or not send_draft_id:
            failures["send_create"] = send_create.status
        if draft_list.status != 200:
            failures["list"] = draft_list.status
        if send_draft_id and status_of(draft_resume) != 200:
            failures["resume"] = status_of(draft_resume)
        if send_draft_id and status_of(send) != 303:
            failures["send"] = status_of(send)
        if send_draft_id and status_of(send_resume) != 404:
            failures["send_resume"] = status_of(send_resume)
        if stale.status == 200:
            failures["stale_session"] = stale.status
        if not static_evidence:
            failures["static_boundary"] = None
        if not redaction_evidence:
            failures["redaction"] = None

        if failures:
            return self.result(
                "OSMAP-WSTG-BUSL-002",
                STATUS_FAIL,
                "draft route evidence did not meet one or more expected outcomes",
                evidence_paths,
                {"statuses": expected_statuses, "failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-BUSL-002",
            STATUS_PASS,
            "draft save, list, resume, delete, send cleanup, CSRF, same-origin, stale-session, attachment-limit, and redaction evidence passed",
            evidence_paths,
            {"statuses": expected_statuses},
        )

    def write_draft_static_boundary_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "draft.rs",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http_gateway_draft.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http" / "routes_draft.rs",
            REPO_ROOT / "docs" / "V3_DRAFT_SAVE_RESUME_DESIGN.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "file_draft_store_scopes_loads_by_owner",
            "expired_drafts_are_removed_on_load",
            "draft_save_existing_load_failed",
            "draft_save_failed",
            "draft_save_request_rejected",
            "draft attachment metadata exceeded maximum count",
            "send_success_deletes_draft_after_accepted_handoff",
            "send_failure_preserves_draft",
            "draft_save_requires_valid_csrf_token",
            "draft_delete_requires_same_origin_request_metadata",
            "audit_session_ref",
            "draft_ref",
            "full draft bodies",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "draft_route_static_boundary.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- owner-scoped file store and cross-owner load isolation\n"
            + "- expired draft cleanup during load/list operations\n"
            + "- generic storage failure and validation responses\n"
            + "- bounded attachment count and byte validation through compose policy\n"
            + "- send-success cleanup and send-failure preservation route tests\n"
            + "- audit fields use draft_ref rather than raw draft ids\n",
        )
        return not missing

    def write_draft_evidence_redaction_evidence(self, forbidden_values: list[str]) -> bool:
        leaks: dict[str, list[str]] = {}
        forbidden_patterns = [
            ("csrf_token_value", re.escape(self.csrf_token) if self.csrf_token else r"$^"),
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
            ("raw_draft_id", r"(?i)(?:/draft\?id=|draft_id=)[0-9a-f]{32}"),
        ]
        for value in forbidden_values:
            if value:
                forbidden_patterns.append((f"value_{len(forbidden_patterns)}", re.escape(value)))
        for path in sorted(self.evidence_dir.glob("draft_*")):
            if path.name == "draft_route_evidence_redaction.txt":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, text)]
            if matches:
                leaks[path.name] = matches
        lines = [
            "Draft evidence redaction scan:",
            "- checked draft_* evidence files only",
            "- raw session cookies, CSRF token values, raw draft ids, generated draft subjects, generated draft bodies, and nonce markers must be absent",
        ]
        if leaks:
            lines.append("Leaks detected:")
            for path, matches in leaks.items():
                lines.append(f"- {path}: {', '.join(matches)}")
        else:
            lines.append("result=passed")
        self.write_text_evidence("draft_route_evidence_redaction.txt", "\n".join(lines) + "\n")
        return not leaks

    def test_source_attachments_authenticated(self) -> TestResult:
        ok, message = self.ensure_login()
        if not ok:
            return self.result("OSMAP-WSTG-BUSL-003", STATUS_SKIP, message)
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-BUSL-003", STATUS_SKIP, "host-assisted live source-attachment evidence disabled")

        evidence_paths = [
            "evidence/source_attachment_live_report.txt",
            "evidence/source_attachment_static_boundary.txt",
            "evidence/source_attachment_evidence_redaction.txt",
        ]
        static_ok = self.write_source_attachment_static_boundary_evidence()
        remote_repo = os.environ.get("OSMAP_WSTG_REMOTE_REPO", "/home/foo/OSMAP")
        expected_ref = os.environ.get("OSMAP_WSTG_EXPECTED_REF", local_git_head())
        live = self.run_ssh(
            "source_attachment_live_report.txt",
            "set -eu; "
            f"cd {shlex.quote(remote_repo)}; "
            "remote_ref=$(git rev-parse HEAD); "
            f"expected_ref={shlex.quote(expected_ref)}; "
            "if [ \"$remote_ref\" != \"$expected_ref\" ]; then "
            "printf 'ERROR: remote repo ref mismatch expected=%s actual=%s\\n' \"$expected_ref\" \"$remote_ref\"; exit 1; "
            "fi; "
            "report=\"$HOME/osmap-wstg-busl-003-source-attachments-$(date +%Y%m%d-%H%M%S).txt\"; "
            "ksh ./maint/live/osmap-live-validate-v3-source-attachments.ksh --report \"$report\" >/tmp/osmap-wstg-busl-003-live.log 2>&1 || { cat /tmp/osmap-wstg-busl-003-live.log; exit 1; }; "
            "cat \"$report\"",
        )
        redaction_ok = self.write_source_attachment_evidence_redaction_evidence()
        required_markers = [
            "osmap_wstg_busl_003_result=passed",
            "credential_proof=real_password_plus_totp_with_temporary_mailbox_hash",
            "positive_send_status=HTTP/1.1 303 See Other",
            "positive_delivered_attachment_status=HTTP/1.1 200 OK",
            "duplicate_selection_status=HTTP/1.1 400 Bad Request",
            "missing_csrf_status=HTTP/1.1 403 Forbidden",
            "cross_origin_status=HTTP/1.1 403 Forbidden",
            "selected_attachment_body_marker_preserved=yes",
            "rejected_cases_delivered=no",
            "audit_original_attachment_budget_observed=yes",
            "secret_review=No password, password hash, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.",
        ]
        missing = [marker for marker in required_markers if marker not in live]
        for prefix in [
            "tampered_mailbox_status=HTTP/1.1 400 Bad Request",
            "tampered_mailbox_status=HTTP/1.1 503 Service Unavailable",
        ]:
            if prefix in live:
                break
        else:
            missing.append("tampered_mailbox_status rejected")
        for prefix in [
            "tampered_uid_status=HTTP/1.1 400 Bad Request",
            "tampered_uid_status=HTTP/1.1 503 Service Unavailable",
        ]:
            if prefix in live:
                break
        else:
            missing.append("tampered_uid_status rejected")
        for prefix in [
            "tampered_part_status=HTTP/1.1 400 Bad Request",
            "tampered_part_status=HTTP/1.1 503 Service Unavailable",
        ]:
            if prefix in live:
                break
        else:
            missing.append("tampered_part_status rejected")
        for prefix in [
            "stale_source_status=HTTP/1.1 400 Bad Request",
            "stale_source_status=HTTP/1.1 503 Service Unavailable",
        ]:
            if prefix in live:
                break
        else:
            missing.append("stale_source_status rejected")

        failures: dict[str, object] = {}
        if "ERROR:" in live:
            failures["ssh"] = "host-assisted live validator was unavailable"
        if not static_ok:
            failures["static_boundary"] = "missing source attachment boundary markers"
        if not redaction_ok:
            failures["redaction"] = "source attachment evidence redaction scan failed"
        if missing:
            failures["missing_live_markers"] = missing
        if failures:
            return self.result(
                "OSMAP-WSTG-BUSL-003",
                STATUS_FAIL,
                "selected source-attachment WSTG evidence did not meet expected outcomes",
                evidence_paths,
                failures,
            )
        return self.result(
            "OSMAP-WSTG-BUSL-003",
            STATUS_PASS,
            "credential-backed selected source-attachment positive, tamper, duplicate, stale, and redaction evidence passed",
            evidence_paths,
        )

    def write_source_attachment_static_boundary_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http_ui.rs",
            REPO_ROOT / "src" / "send.rs",
            REPO_ROOT / "docs" / "V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md",
            REPO_ROOT / "maint" / "live" / "osmap-live-validate-v3-source-attachments.ksh",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "selected_original_attachment_parts",
            "include_original_attachment_",
            "source_mailbox",
            "source_uid",
            "original_attachment_send",
            "http_send_original_attachment_selection_rejected",
            "http_send_original_attachment_fetch_failed",
            "osmap_wstg_busl_003_result=passed",
            "real_password_plus_totp_with_temporary_mailbox_hash",
            "OSMAP-WSTG-BUSL-003",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "source_attachment_static_boundary.txt",
            summarize_static_files(files, missing)
            + "\nCovered boundaries:\n"
            + "- explicit source attachment selection fields only\n"
            + "- send-time helper-backed source attachment re-fetch\n"
            + "- duplicate, tampered, stale, CSRF, and same-origin rejection evidence\n"
            + "- selected source attachments share compose attachment limits\n"
            + "- report redaction excludes credentials, tokens, message bodies, and attachment bodies\n",
        )
        return not missing

    def write_source_attachment_evidence_redaction_evidence(self) -> bool:
        leaks: dict[str, list[str]] = {}
        forbidden_patterns = [
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
            ("csrf_token_value", r"(?i)csrf_token=[A-Za-z0-9._~+/=-]{16,}"),
            ("password_hash", r"\$2[aby]\$[0-9]{2}\$"),
            ("totp_secret", r"(?i)(totp|secret)[_=][A-Z2-7]{16,}"),
            ("attachment_body_marker", r"osmap selected source attachment marker"),
            ("private_body_text", r"selected source attachment proof body"),
        ]
        for path in sorted(self.evidence_dir.glob("source_attachment_*")):
            if path.name == "source_attachment_evidence_redaction.txt":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, text)]
            if matches:
                leaks[path.name] = matches
        lines = [
            "Source attachment evidence redaction scan:",
            "- checked source_attachment_* evidence files only",
            "- raw session cookies, CSRF token values, password hashes, TOTP secrets, generated message bodies, and attachment body markers must be absent",
        ]
        if leaks:
            lines.append("Leaks detected:")
            for path, matches in leaks.items():
                lines.append(f"- {path}: {', '.join(matches)}")
        else:
            lines.append("result=passed")
        self.write_text_evidence("source_attachment_evidence_redaction.txt", "\n".join(lines) + "\n")
        return not leaks

    def test_form_route_state_transitions_static(self) -> TestResult:
        static_ok = self.write_form_route_state_transitions_static_evidence()
        evidence = ["evidence/form_route_state_transitions_static.txt"]
        if not static_ok:
            return self.result("OSMAP-WSTG-BUSL-005", STATUS_FAIL, "form-backed route and state-transition evidence is missing expected guards", evidence)
        return self.result("OSMAP-WSTG-BUSL-005", STATUS_PASS, "form-backed route inventory and state-transition guard evidence is present", evidence)

    def write_form_route_state_transitions_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http_form.rs",
            REPO_ROOT / "src" / "http" / "routes_auth.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http" / "routes_draft.rs",
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "src" / "http" / "routes_settings.rs",
            REPO_ROOT / "docs" / "V3_FORM_ROUTE_STATE_TRANSITIONS.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-BUSL-005",
            "WSTG-v42-BUSL-01",
            "WSTG-v42-BUSL-02",
            "WSTG-v42-BUSL-03",
            "WSTG-v42-BUSL-05",
            "WSTG-v42-BUSL-06",
            "WSTG-v42-BUSL-07",
            "require_valid_csrf",
            "authenticated_post_routes_reject_cross_origin_headers",
            "rejects_duplicate_urlencoded_fields",
            "message_move_rejects_tampered_invalid_uid_without_success_redirect",
            "message_move_rejects_mismatched_mailbox_uid_tuple",
            "bulk_move_rejects_oversized_selection_before_moving",
            "draft_delete_removes_saved_draft",
            "send_success_deletes_draft_after_accepted_handoff",
            "send_failure_preserves_draft",
            "session_revoke_all_sessions_clears_current_cookie",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "form_route_state_transitions_static.txt",
            summarize_static_files(files, missing)
            + "\nRoute/state decisions:\n"
            + "- OSMAP has browser form-backed routes, not JSON/REST API routes.\n"
            + "- state-changing form routes require authenticated sessions, CSRF, and same-origin request metadata.\n"
            + "- duplicate fields, malformed IDs, tampered mailbox/UID pairs, oversized bulk actions, and stale draft transitions fail closed.\n"
            + "- successful send deletes the accepted draft while failed send preserves it for retry.\n",
        )
        return not missing

    def test_graphql_applicability_static(self) -> TestResult:
        source_files = list(sorted((REPO_ROOT / "src").glob("*.rs"))) + [REPO_ROOT / "Cargo.toml", REPO_ROOT / "Cargo.lock"]
        source_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in source_files if path.exists()).lower()
        markers = ["graphql", "juniper", "async-graphql", "/graphql"]
        matched = [marker for marker in markers if marker in source_text]
        static_ok = self.write_graphql_applicability_static_evidence(matched)
        evidence = ["evidence/graphql_applicability_static.txt"]
        if matched or not static_ok:
            return self.result("OSMAP-WSTG-APIT-001", STATUS_FAIL, "GraphQL/API applicability review found unexpected source markers", evidence, {"unexpected_markers": matched})
        return self.result("OSMAP-WSTG-APIT-001", STATUS_PASS, "GraphQL is not applicable; OSMAP exposes browser form routes rather than API routes", evidence, {"markers_checked": markers})

    def write_graphql_applicability_static_evidence(self, matched: list[str]) -> bool:
        files = [
            REPO_ROOT / "Cargo.toml",
            REPO_ROOT / "Cargo.lock",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http" / "routes_auth.rs",
            REPO_ROOT / "src" / "http" / "routes_compose.rs",
            REPO_ROOT / "src" / "http" / "routes_draft.rs",
            REPO_ROOT / "src" / "http" / "routes_mail.rs",
            REPO_ROOT / "src" / "http" / "routes_settings.rs",
            REPO_ROOT / "docs" / "V3_FORM_ROUTE_STATE_TRANSITIONS.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-APIT-001",
            "WSTG-v42-APIT-01",
            "no GraphQL endpoint",
            "no GraphQL dependency",
            "browser form routes rather than API routes",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Applicability decisions:",
            "- GraphQL is not applicable; OSMAP has no GraphQL endpoint, schema, resolver layer, or GraphQL dependency.",
            "- OSMAP exposes browser form routes rather than API routes; state-transition evidence is tracked under OSMAP-WSTG-BUSL-005.",
        ]
        if matched:
            lines.extend(["", "Unexpected GraphQL markers:", json.dumps(matched, indent=2)])
        self.write_text_evidence("graphql_applicability_static.txt", "\n".join(lines) + "\n")
        return not missing

    def test_host_bindings(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-CONF-005", STATUS_SKIP, "host-assisted tests disabled")
        services = self.run_ssh(
            "host_services.txt",
            "hostname; rcctl check nginx || true; rcctl check osmap_serve || true; rcctl check osmap_mailbox_helper || true",
        )
        bindings = self.run_ssh(
            "host_bindings.txt",
            "netstat -an -f inet | egrep '(\\.443|\\.8080|\\.25|\\.587|\\.993).*LISTEN' || true",
        )
        nginx = self.run_ssh(
            "host_nginx.txt",
            "doas nginx -T 2>/dev/null | egrep 'server_name mail.blackbagsecurity.com|proxy_pass http://127.0.0.1:8080|limit_except GET POST|listen .*443|include /etc/nginx/templates/osmap-root.tmpl' | head -80",
        )
        combined = f"{services}\n{bindings}\n{nginx}"
        if "ERROR:" in combined:
            return self.result(
                "OSMAP-WSTG-CONF-005",
                STATUS_WARNING,
                "host-assisted SSH evidence was unavailable from the current network path",
                ["evidence/host_services.txt", "evidence/host_bindings.txt", "evidence/host_nginx.txt"],
            )
        required = ["nginx(ok)", "osmap_serve(ok)", "osmap_mailbox_helper(ok)", "127.0.0.1.8080", "proxy_pass http://127.0.0.1:8080"]
        missing = [item for item in required if item not in combined]
        if missing:
            return self.result("OSMAP-WSTG-CONF-005", STATUS_FAIL, "host service or binding evidence is missing expected markers", ["evidence/host_services.txt", "evidence/host_bindings.txt", "evidence/host_nginx.txt"], {"missing": missing})
        return self.result("OSMAP-WSTG-CONF-005", STATUS_PASS, "host shows nginx and OSMAP services running with loopback OSMAP binding", ["evidence/host_services.txt", "evidence/host_bindings.txt", "evidence/host_nginx.txt"])

    def test_host_pf(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-WSTG-CONF-006", STATUS_SKIP, "host-assisted tests disabled")
        pf = self.run_ssh(
            "host_pf.txt",
            "doas pfctl -s info 2>/dev/null | head -40; printf '\\n--- rules ---\\n'; doas pfctl -sr 2>/dev/null | head -120",
        )
        if "ERROR:" in pf:
            return self.result(
                "OSMAP-WSTG-CONF-006",
                STATUS_WARNING,
                "host-assisted SSH pf evidence was unavailable from the current network path",
                ["evidence/host_pf.txt"],
            )
        if "Status: Enabled" not in pf or "block drop" not in pf:
            return self.result("OSMAP-WSTG-CONF-006", STATUS_FAIL, "pf evidence does not show enabled default-drop posture", ["evidence/host_pf.txt"])
        return self.result("OSMAP-WSTG-CONF-006", STATUS_PASS, "pf is enabled and rules include drop posture", ["evidence/host_pf.txt"])

    def test_dependency_alignment(self) -> TestResult:
        files = [
            REPO_ROOT / "Cargo.lock",
            REPO_ROOT / "docs" / "SUPPLY_CHAIN_POLICY.md",
            REPO_ROOT / "maint" / "security" / "osmap-security-check.sh",
        ]
        missing_files = [str(path.relative_to(REPO_ROOT)) for path in files if not path.exists()]
        evidence = self.write_text_evidence(
            "static_dependency_alignment.txt",
            "Checked dependency and supply-chain files:\n"
            + "\n".join(f"- {path.relative_to(REPO_ROOT)}: {'present' if path.exists() else 'missing'}" for path in files),
        )
        metadata_text = ""
        metadata_ok = False
        try:
            completed = subprocess.run(
                ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
            metadata_text = completed.stdout
            metadata_ok = completed.returncode == 0 and '"packages"' in metadata_text and '"workspace_members"' in metadata_text
        except (OSError, subprocess.TimeoutExpired) as exc:
            metadata_text = f"ERROR: {exc}\n"
        metadata_evidence = self.write_text_evidence("dependency_metadata_locked.txt", metadata_text)
        if missing_files:
            return self.result("OSMAP-WSTG-CONF-007", STATUS_FAIL, "dependency alignment files are missing", [evidence, metadata_evidence], {"missing": missing_files})
        if not metadata_ok:
            return self.result("OSMAP-WSTG-CONF-007", STATUS_FAIL, "locked dependency metadata command failed", [evidence, metadata_evidence])
        return self.result("OSMAP-WSTG-CONF-007", STATUS_PASS, "lockfile, supply-chain policy, and locked dependency metadata validated", [evidence, metadata_evidence])

    def test_crypto_transport_security(self) -> TestResult:
        https = self.request("crypto_https_login", "GET", "/login")
        hsts = https.first_header("Strict-Transport-Security")
        http = self.request("crypto_cleartext_login", "GET", "/login", scheme="http", port=80)
        static_ok = self.write_crypto_transport_static_evidence()
        tls_guard, tls_report, tls_stdout, tls_ok, tls_details = self.write_crypto_tls_standard_evidence()
        evidence_paths = [
            "evidence/crypto_https_login.headers",
            "evidence/crypto_cleartext_login.headers",
            "evidence/crypto_transport_static.txt",
            tls_guard,
            tls_report,
            tls_stdout,
        ]
        failures: dict[str, object] = {}
        if self.config.scheme != "https":
            failures["base_url_scheme"] = self.config.scheme
        if https.status != 200:
            failures["https_login_status"] = https.status or https.error
        if "max-age=" not in hsts.lower():
            failures["hsts"] = hsts or "missing"
        if http.status in {301, 302, 307, 308}:
            location = http.first_header("Location")
            if not (location.startswith("https://") or location.startswith(self.config.base_url)):
                failures["cleartext_redirect_location"] = location
        elif http.status is None:
            pass
        else:
            failures["cleartext_http_status"] = http.status
        if not static_ok:
            failures["static_boundary"] = "missing crypto transport markers"
        if not tls_ok:
            failures["tls_standard"] = tls_details
        if failures:
            return self.result(
                "OSMAP-WSTG-CRYP-001",
                STATUS_FAIL,
                "weak-transport or cleartext-channel evidence did not meet the TLS standard",
                evidence_paths,
                {"failures": failures},
            )
        return self.result(
            "OSMAP-WSTG-CRYP-001",
            STATUS_PASS,
            "TLS standard, HSTS, HTTPS login, and cleartext HTTP controls passed",
            evidence_paths,
            {"tls_standard": tls_details},
        )

    def write_crypto_tls_standard_evidence(self) -> tuple[str, str, str, bool, dict[str, object]]:
        guard = subprocess.run(
            ["sh", "maint/security/osmap-tls-policy-guard.sh"],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        guard_path = self.write_text_evidence("crypto_tls_policy_guard.txt", guard.stdout)
        report_path = self.evidence_dir / "crypto_tls_standard_report.json"
        stdout_path = self.evidence_dir / "crypto_tls_standard_validate.txt"
        command = [
            sys.executable,
            "maint/security/osmap-live-tls-standard-validate.py",
            self.config.base_url,
            "--report",
            str(report_path),
            "--timeout",
            str(self.config.timeout),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=max(30.0, self.config.timeout * 8),
                check=False,
            )
            stdout_path.write_text(self.redact(completed.stdout), encoding="utf-8")
            returncode = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            stdout_path.write_text(f"ERROR: {exc}\n", encoding="utf-8")
            returncode = 124 if isinstance(exc, subprocess.TimeoutExpired) else 127
        details: dict[str, object] = {"guard_returncode": guard.returncode, "validator_returncode": returncode}
        report_ok = False
        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report_ok = report.get("result") == "tls_standard_passed"
                details.update(
                    {
                        "result": report.get("result"),
                        "minimum_tls_version": report.get("minimum_tls_version"),
                        "preferred_tls_version": report.get("preferred_tls_version"),
                        "certificate_validation": report.get("certificate_validation"),
                        "hostname_validation": report.get("hostname_validation"),
                        "failures": report.get("failures", []),
                    }
                )
            except json.JSONDecodeError as exc:
                details["report_error"] = str(exc)
        else:
            report_path.write_text("ERROR: TLS standard validator did not write report\n", encoding="utf-8")
            details["report_error"] = "missing report"
        ok = guard.returncode == 0 and returncode == 0 and report_ok
        return (
            guard_path,
            str(report_path.relative_to(self.run_dir)),
            str(stdout_path.relative_to(self.run_dir)),
            ok,
            details,
        )

    def write_crypto_transport_static_evidence(self) -> bool:
        files = [
            REPO_ROOT / "docs" / "TLS_STANDARD.md",
            REPO_ROOT / "docs" / "HTTP_HARDENING_BASELINE.md",
            REPO_ROOT / "docs" / "V3_CRYPTO_TRANSPORT_EVIDENCE.md",
            REPO_ROOT / "src" / "http.rs",
            REPO_ROOT / "src" / "http_parse.rs",
            REPO_ROOT / "maint" / "security" / "osmap-tls-policy-guard.sh",
            REPO_ROOT / "maint" / "security" / "osmap-live-tls-standard-validate.py",
            REPO_ROOT / "maint" / "openbsd" / "mail.blackbagsecurity.com" / "nginx" / "templates" / "osmap-root.tmpl",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-CRYP-001",
            "WSTG-v42-CRYP-01",
            "WSTG-v42-CRYP-03",
            "TLS 1.2 is the minimum allowed protocol version.",
            "TLS 1.3 is preferred where supported.",
            "CBC-mode legacy suites are prohibited.",
            "Strict-Transport-Security",
            "build_session_cookie",
            "Secure",
            "X-Forwarded-Proto https",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        self.write_text_evidence(
            "crypto_transport_static.txt",
            summarize_static_files(files, missing)
            + "\nTransport decisions:\n"
            + "- public TLS terminates at nginx with TLS 1.2 minimum and TLS 1.3 preferred.\n"
            + "- weak protocols and legacy TLS 1.2 ciphers are rejected by the live TLS standard validator.\n"
            + "- browser login evidence is collected over HTTPS and the cleartext listener must redirect or be unreachable.\n"
            + "- production session cookies are marked Secure and the reverse proxy forwards HTTPS scheme context.\n",
        )
        return not missing

    def test_crypto_primitive_applicability_static(self) -> TestResult:
        source_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted((REPO_ROOT / "src").glob("*.rs"))
        ).lower()
        banned_source_markers = [
            "decrypt(",
            "encrypt(",
            "openssl::",
            "ring::aead",
            "aes::",
            "cbc::",
            "block_modes",
            "pkcs7",
            "rsa::",
        ]
        matched = [marker for marker in banned_source_markers if marker in source_text]
        static_ok = self.write_crypto_primitive_applicability_evidence(matched)
        evidence_paths = ["evidence/crypto_primitive_applicability_static.txt"]
        if matched or not static_ok:
            return self.result(
                "OSMAP-WSTG-CRYP-002",
                STATUS_FAIL,
                "cryptographic primitive applicability review found unexpected reversible-crypto surfaces",
                evidence_paths,
                {"unexpected_source_markers": matched},
            )
        return self.result(
            "OSMAP-WSTG-CRYP-002",
            STATUS_PASS,
            "padding-oracle and weak-encryption rows are not applicable to the current OSMAP browser surface",
            evidence_paths,
            {"source_markers_checked": banned_source_markers},
        )

    def write_crypto_primitive_applicability_evidence(self, matched: list[str]) -> bool:
        files = [
            REPO_ROOT / "Cargo.toml",
            REPO_ROOT / "Cargo.lock",
            REPO_ROOT / "src" / "session.rs",
            REPO_ROOT / "src" / "totp.rs",
            REPO_ROOT / "src" / "http_parse.rs",
            REPO_ROOT / "docs" / "TLS_STANDARD.md",
            REPO_ROOT / "docs" / "V3_CRYPTO_TRANSPORT_EVIDENCE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "OSMAP-WSTG-CRYP-002",
            "WSTG-v42-CRYP-02",
            "WSTG-v42-CRYP-04",
            "no application encryption/decryption primitive",
            "no CBC decryptor",
            "no padding oracle surface",
            "no custom reversible encryption",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        lines = [
            summarize_static_files(files, missing),
            "",
            "Applicability decisions:",
            "- Padding oracle: not applicable; OSMAP has no application encryption/decryption primitive, no CBC decryptor, and no attacker-controlled ciphertext decrypt route.",
            "- Weak encryption: not applicable; OSMAP has no custom reversible encryption or browser-exposed cryptographic primitive.",
            "- Current cryptographic use is limited to TOTP HMAC-SHA1 verification, session-token randomness, and non-reversible token references/hashes; public transport cryptography is delegated to the nginx TLS edge and validated separately.",
        ]
        if matched:
            lines.extend(["", "Unexpected reversible-crypto markers:", json.dumps(matched, indent=2)])
        self.write_text_evidence("crypto_primitive_applicability_static.txt", "\n".join(lines) + "\n")
        return not missing

    def test_security_logging_static(self) -> TestResult:
        files = [
            REPO_ROOT / "src" / "auth.rs",
            REPO_ROOT / "src" / "session.rs",
            REPO_ROOT / "src" / "logging.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "docs" / "OBSERVABILITY_AND_MONITORING.md",
            REPO_ROOT / "docs" / "REQUEST_WORKER_BUDGET_MODEL.md",
            REPO_ROOT / "maint" / "security" / "osmap-release-check.sh",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = [
            "audit_session_ref",
            "redact",
            "session_ref",
            "auth",
            "session",
            "request_id",
            "password",
            "TOTP",
            "CSRF",
            "message body",
            "skipped_checks",
        ]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        static_evidence = self.write_text_evidence("static_security_logging.txt", summarize_static_files(files, missing))
        leaks: dict[str, list[str]] = {}
        dynamic_files = [
            path
            for path in sorted(self.evidence_dir.iterdir())
            if path.is_file() and not path.name.startswith("static_") and path.name != "security_logging_evidence_redaction.txt"
        ]
        forbidden_patterns = [
            ("raw_session_cookie", r"osmap_session=[A-Za-z0-9._~+/=-]+"),
            ("csrf_token_value", r"(?i)csrf_token=(?!\[REDACTED\])[^&\s\"']+"),
            ("csrf_token_field", r'(?i)name=["\']csrf_token["\']\s+value=["\'](?!\[REDACTED\])[^"\']+["\']'),
            ("password_hash", r"\$2[aby]\$[0-9]{2}\$"),
            ("totp_secret", r"(?i)(totp_secret|totp seed|otpauth://|secret=)[A-Z2-7]{16,}"),
            ("authorization_secret", r"(?i)authorization:\s*(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
        ]
        for path in dynamic_files:
            body = path.read_text(encoding="utf-8", errors="replace")
            matches = [name for name, pattern in forbidden_patterns if re.search(pattern, body)]
            if matches:
                leaks[path.name] = matches
        redaction_lines = [
            "Security logging and evidence redaction scan:",
            "- checked dynamic WSTG evidence files",
            "- raw session cookies, CSRF token values, password hashes, TOTP material, and authorization secrets must be absent",
        ]
        if dynamic_files:
            redaction_lines.append(f"checked_files={len(dynamic_files)}")
        else:
            redaction_lines.append("checked_files=0")
        if leaks:
            for path, matches in leaks.items():
                redaction_lines.append(f"- {path}: {', '.join(matches)}")
        else:
            redaction_lines.append("result=passed")
        redaction_evidence = self.write_text_evidence("security_logging_evidence_redaction.txt", "\n".join(redaction_lines) + "\n")
        if missing:
            return self.result(
                "OSMAP-WSTG-LOGG-001",
                STATUS_FAIL,
                "security logging and redaction markers were missing from source/docs",
                [static_evidence, redaction_evidence],
                {"missing": missing},
            )
        if leaks:
            return self.result(
                "OSMAP-WSTG-LOGG-001",
                STATUS_FAIL,
                "dynamic WSTG evidence disclosed sensitive logging or token material",
                [static_evidence, redaction_evidence],
                {"leaks": leaks},
            )
        return self.result(
            "OSMAP-WSTG-LOGG-001",
            STATUS_PASS,
            "structured logging markers and dynamic evidence redaction scan passed",
            [static_evidence, redaction_evidence],
        )

    def run_ssh(self, filename: str, command: str) -> str:
        try:
            completed = subprocess.run(
                ["ssh", self.config.ssh_host, command],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=self.config.ssh_timeout,
            )
            output = completed.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = f"ERROR: {exc}\n"
        self.write_text_evidence(filename, output)
        return output


def same_origin_headers(config: Config) -> dict[str, str]:
    return {"Origin": f"{config.scheme}://{config.host}", "Referer": f"{config.base_url}/mailboxes"}


def local_git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def extract_csrf(text: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', text)
    return match.group(1) if match else ""


def cookie_jar_from_set_cookie_headers(headers: list[str]) -> dict[str, str]:
    jar: dict[str, str] = {}
    for header in headers:
        first = header.split(";", 1)[0]
        if "=" in first:
            name, value = first.split("=", 1)
            jar[name] = value
    return jar


def draft_id_from_location(location: str) -> str:
    parsed = urllib.parse.urlparse(location)
    query = urllib.parse.parse_qs(parsed.query)
    draft_id = query.get("id", [""])[0]
    return draft_id if re.fullmatch(r"[0-9a-f]{32}", draft_id) else ""


def status_of(evidence: HttpEvidence | None) -> int | None:
    return evidence.status if evidence else None


def build_multipart_form(
    boundary: str,
    fields: dict[str, str],
    files: list[tuple[str, str, str, bytes]],
) -> bytes:
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")
    for name, filename, content_type, content in files:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode("utf-8")
        )
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body)


def command_injection_payloads(input_marker: str, output_canary: str) -> list[dict[str, object]]:
    separator_canary = f"{input_marker}; printf {output_canary}"
    return [
        {
            "name": "separator_canary",
            "class": "shell separator with output canary",
            "payload": separator_canary,
            "timing_probe": False,
        },
        {
            "name": "separator_uid",
            "class": "shell separator with uid/gid output probe",
            "payload": f"{input_marker}; id",
            "timing_probe": False,
        },
        {
            "name": "command_substitution_canary",
            "class": "command substitution syntax with output canary",
            "payload": f"{input_marker}$(printf {output_canary})",
            "timing_probe": False,
        },
        {
            "name": "command_substitution_uid",
            "class": "command substitution syntax with uid/gid output probe",
            "payload": f"{input_marker}$(id)",
            "timing_probe": False,
        },
        {
            "name": "redirect",
            "class": "redirect metacharacters",
            "payload": f"{input_marker} 2>&1 >/dev/null",
            "timing_probe": False,
        },
        {
            "name": "newline_canary",
            "class": "newline command separator with output canary",
            "payload": f"{input_marker}\nprintf {output_canary}",
            "timing_probe": False,
        },
        {
            "name": "double_encoded_separator",
            "class": "double-encoded shell separator with output canary",
            "payload": urllib.parse.quote(separator_canary, safe=""),
            "timing_probe": False,
        },
        {
            "name": "bounded_timing",
            "class": "bounded timing probe",
            "payload": f"{input_marker}; sleep {COMMAND_INJECTION_SLEEP_SECONDS}",
            "timing_probe": True,
        },
    ]


def command_injection_surfaces(config: Config, csrf_token: str) -> list[dict[str, object]]:
    invalid_csrf = f"invalid-inpv12-{csrf_token[:8] if csrf_token else 'missing'}"
    mutation_headers = same_origin_headers(config)
    return [
        {
            "name": "unauth_login",
            "authenticated": False,
            "method": "GET",
            "path": "/login?inpv12={payload}",
        },
        {
            "name": "unauth_mailbox",
            "authenticated": False,
            "method": "GET",
            "path": "/mailbox?name={payload}",
        },
        {
            "name": "unauth_message",
            "authenticated": False,
            "method": "GET",
            "path": "/message?mailbox={payload}&uid=1",
        },
        {
            "name": "unauth_attachment",
            "authenticated": False,
            "method": "GET",
            "path": "/attachment?mailbox={payload}&uid=1&part=1",
        },
        {
            "name": "unauth_search",
            "authenticated": False,
            "method": "GET",
            "path": "/search?q={payload}",
        },
        {
            "name": "unauth_drafts_save",
            "authenticated": False,
            "method": "POST",
            "path": "/drafts/save",
            "headers": mutation_headers,
            "fields": {
                "csrf_token": invalid_csrf,
                "to": config.test_email or "wstg@example.invalid",
                "subject": "{payload}",
                "body": "{payload}",
            },
        },
        {
            "name": "unauth_send",
            "authenticated": False,
            "method": "POST",
            "path": "/send",
            "headers": mutation_headers,
            "fields": {
                "csrf_token": invalid_csrf,
                "to": config.test_email or "wstg@example.invalid",
                "subject": "{payload}",
                "body": "{payload}",
            },
        },
        {
            "name": "unauth_messages_move",
            "authenticated": False,
            "method": "POST",
            "path": "/messages/move",
            "headers": mutation_headers,
            "fields": {
                "csrf_token": invalid_csrf,
                "mailbox": "{payload}",
                "destination_mailbox": "{payload}",
                "uid_1": "1",
            },
        },
        {
            "name": "auth_login",
            "authenticated": True,
            "method": "GET",
            "path": "/login?inpv12={payload}",
        },
        {
            "name": "auth_mailbox",
            "authenticated": True,
            "method": "GET",
            "path": "/mailbox?name={payload}",
        },
        {
            "name": "auth_message",
            "authenticated": True,
            "method": "GET",
            "path": "/message?mailbox={payload}&uid=1",
        },
        {
            "name": "auth_attachment",
            "authenticated": True,
            "method": "GET",
            "path": "/attachment?mailbox={payload}&uid=1&part=1",
        },
        {
            "name": "auth_search",
            "authenticated": True,
            "method": "GET",
            "path": "/search?q={payload}",
        },
        {
            "name": "auth_drafts_save",
            "authenticated": True,
            "method": "POST",
            "path": "/drafts/save",
            "headers": mutation_headers,
            "fields": {
                "csrf_token": invalid_csrf,
                "to": config.test_email or "wstg@example.invalid",
                "subject": "{payload}",
                "body": "{payload}",
            },
        },
        {
            "name": "auth_send",
            "authenticated": True,
            "method": "POST",
            "path": "/send",
            "headers": mutation_headers,
            "fields": {
                "csrf_token": invalid_csrf,
                "to": config.test_email or "wstg@example.invalid",
                "subject": "{payload}",
                "body": "{payload}",
            },
        },
        {
            "name": "auth_messages_move",
            "authenticated": True,
            "method": "POST",
            "path": "/messages/move",
            "headers": mutation_headers,
            "fields": {
                "csrf_token": invalid_csrf,
                "mailbox": "{payload}",
                "destination_mailbox": "{payload}",
                "uid_1": "1",
            },
        },
    ]


def command_injection_findings(
    evidence: HttpEvidence,
    *,
    raw_payload: str,
    output_canary: str,
    elapsed: float,
    baseline_elapsed: float,
    timing_probe: bool,
) -> list[str]:
    text = evidence.body_text()
    header_text = "\n".join(f"{key}: {value}" for key, value in evidence.headers)
    combined = f"{text}\n{header_text}"
    findings = command_injection_text_findings(
        combined,
        output_canary=output_canary,
        source_payloads=[raw_payload],
    )
    if evidence.truncated:
        findings.append("response_truncated_before_absence_assertions_completed")
    if evidence.status == 500:
        findings.append("http_500")
    if evidence.status is None:
        findings.append("request_error")
    if timing_probe:
        timing_threshold = max(baseline_elapsed + 1.5, baseline_elapsed * 3.0 + 0.5)
        if elapsed >= timing_threshold and elapsed >= COMMAND_INJECTION_SLEEP_SECONDS * 0.75:
            findings.append(
                f"abnormal_timing elapsed={elapsed:.3f}s baseline={baseline_elapsed:.3f}s"
            )
    return findings


def command_injection_text_findings(
    text: str,
    *,
    output_canary: str,
    source_payloads: list[str],
) -> list[str]:
    normalized = html.unescape(text)
    findings: list[str] = []
    if output_canary in normalized:
        source_reflected = any(payload and payload in normalized for payload in source_payloads)
        command_source_reflected = any(
            marker in normalized
            for marker in [
                f"printf {output_canary}",
                f"echo {output_canary}",
                urllib.parse.quote(output_canary, safe=""),
            ]
        )
        if not source_reflected and not command_source_reflected:
            findings.append("reflected_command_output_canary")
    if re.search(r"\buid=\d+(?:\([^)]+\))?\s+gid=\d+", normalized):
        findings.append("uid_gid_output")
    if re.search(r"(?m)^root:[^:\n]*:\d+:\d+:", normalized):
        findings.append("passwd_style_output")
    for pattern in COMMAND_INJECTION_DIAGNOSTIC_PATTERNS:
        if re.search(pattern, normalized):
            findings.append("shell_or_openbsd_diagnostic_leakage")
            break
    for pattern in COMMAND_INJECTION_PANIC_PATTERNS:
        if re.search(pattern, normalized):
            findings.append("panic_or_stack_trace_leakage")
            break
    return findings


def safe_label(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
    return safe.strip("_") or "evidence"


def summarize_static_files(files: list[Path], missing: list[str]) -> str:
    lines = ["Static review evidence:"]
    for path in files:
        lines.append(f"- {path}: {'present' if path.exists() else 'missing'}")
    if missing:
        lines.append("Missing markers:")
        lines.extend(f"- {marker}" for marker in missing)
    return "\n".join(lines) + "\n"


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            parsed = shlex.split(value, comments=False, posix=True)
            values[key] = parsed[0] if parsed else ""
        except ValueError:
            values[key] = value.strip("\"'")
    return values


def build_config(args: argparse.Namespace) -> Config:
    env_values = {}
    env_values.update(load_env_file(PACK_ROOT / ".env"))
    merged = dict(os.environ)
    merged.update(env_values)

    base_url = args.base_url or merged.get("OSMAP_BASE_URL") or "https://mail.blackbagsecurity.com"
    parsed = urllib.parse.urlparse(base_url)
    host = args.host or merged.get("OSMAP_HOST") or parsed.hostname or "mail.blackbagsecurity.com"
    output_root_raw = args.output_dir or merged.get("OSMAP_OUTPUT_DIR")
    output_root = Path(output_root_raw).expanduser() if output_root_raw else PACK_ROOT / "output"
    allow_host = args.include_host or parse_bool(merged.get("OSMAP_ALLOW_HOST_ASSISTED_TESTS"), False)
    if args.no_host:
        allow_host = False
    allow_auth = parse_bool(merged.get("OSMAP_ALLOW_AUTHENTICATED_TESTS"), False)
    if args.authenticated:
        allow_auth = True
    if args.prompt_auth:
        allow_auth = True
    if args.unauthenticated:
        allow_auth = False
    prompt_auth = args.prompt_auth or parse_bool(merged.get("OSMAP_PROMPT_AUTH"), False)
    release_mode = (
        args.release
        or merged.get("OSMAP_WSTG_PROFILE") == "release"
        or merged.get("OSMAP_SECURITY_PROFILE") == "release"
    )
    throttle_attempts_default = "6" if release_mode else "3"
    throttle_attempts_raw = merged.get("OSMAP_THROTTLE_PROBE_ATTEMPTS", throttle_attempts_default)
    if release_mode:
        allow_auth = True
        allow_host = True
    return Config(
        base_url=base_url.rstrip("/"),
        host=host,
        ssh_host=merged.get("OSMAP_SSH_HOST", "mail.blackbagsecurity.com"),
        test_email=args.auth_email or merged.get("OSMAP_TEST_EMAIL", ""),
        test_password=merged.get("OSMAP_TEST_PASSWORD", ""),
        totp_secret=merged.get("OSMAP_TOTP_SECRET", ""),
        secondary_email=merged.get("OSMAP_SECONDARY_EMAIL", ""),
        output_dir=output_root,
        rate_delay=float(merged.get("OSMAP_RATE_LIMIT_DELAY_SECONDS", "1") or "1"),
        allow_authenticated=allow_auth,
        prompt_auth=prompt_auth,
        allow_host_assisted=allow_host,
        throttle_attempts=max(1, int(throttle_attempts_raw or throttle_attempts_default)),
        timeout=float(merged.get("OSMAP_REQUEST_TIMEOUT_SECONDS", "12") or "12"),
        ssh_timeout=max(1.0, float(merged.get("OSMAP_SSH_TIMEOUT_SECONDS", "300") or "300")),
        release_mode=release_mode,
        wstg_source_name=merged.get("OSMAP_WSTG_SOURCE_NAME", "OWASP Web Security Testing Guide"),
        wstg_source_url=merged.get("OSMAP_WSTG_SOURCE_URL", "https://owasp.org/www-project-web-security-testing-guide/v42/"),
        wstg_source_version=merged.get("OSMAP_WSTG_SOURCE_VERSION", "v4.2"),
        wstg_source_commit=merged.get("OSMAP_WSTG_SOURCE_COMMIT", ""),
        wstg_matrix_file=merged.get("OSMAP_WSTG_MATRIX_FILE", DEFAULT_WSTG_MATRIX_FILE),
    )


def generate_totp(secret: str, *, timestamp: int | None = None, digits: int = 6, period: int = 30) -> str:
    cleaned = re.sub(r"\s+", "", secret)
    if cleaned.lower().startswith("otpauth://"):
        parsed = urllib.parse.urlparse(cleaned)
        query = urllib.parse.parse_qs(parsed.query)
        cleaned = query.get("secret", [""])[0]
    cleaned = cleaned.upper()
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    key = base64.b32decode(cleaned + padding, casefold=True)
    counter = int((timestamp or int(time.time())) / period)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def active_matrix_metadata(config: Config) -> dict[str, object]:
    matrix_path = (PACK_ROOT / config.wstg_matrix_file).resolve()
    try:
        relative_matrix = str(matrix_path.relative_to(PACK_ROOT))
    except ValueError:
        relative_matrix = str(matrix_path)

    metadata: dict[str, object] = {
        "matrix_file": relative_matrix,
        "exists": matrix_path.is_file(),
        "scenario_count": 0,
        "disposition_counts": {},
        "missing_disposition_count": 0,
        "invalid_disposition_count": 0,
    }
    if not matrix_path.is_file():
        return metadata

    try:
        payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        metadata["error"] = str(error)
        return metadata

    scenarios = payload.get("scenarios", [])
    if not isinstance(scenarios, list):
        metadata["error"] = "matrix scenarios field was not a list"
        return metadata

    disposition_counts: dict[str, int] = {}
    missing = 0
    invalid = 0
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            invalid += 1
            continue
        disposition = str(scenario.get("disposition", "")).strip()
        if not disposition:
            missing += 1
            continue
        disposition_counts[disposition] = disposition_counts.get(disposition, 0) + 1
        if disposition not in ALLOWED_MATRIX_DISPOSITIONS:
            invalid += 1

    metadata["scenario_count"] = len(scenarios)
    metadata["disposition_counts"] = disposition_counts
    metadata["missing_disposition_count"] = missing
    metadata["invalid_disposition_count"] = invalid
    metadata["wstg_source"] = payload.get("wstg_source", "")
    return metadata


def wstg_source_metadata(runner: Runner, matrix_metadata: dict[str, object]) -> dict[str, object]:
    if runner.config.prompt_auth:
        auth_mode = "prompt-auth"
    elif runner.config.allow_authenticated:
        auth_mode = "authenticated"
    else:
        auth_mode = "unauthenticated"

    return {
        "source_name": runner.config.wstg_source_name,
        "source_url": runner.config.wstg_source_url,
        "source_version": runner.config.wstg_source_version,
        "source_commit": runner.config.wstg_source_commit,
        "capture_date": dt.datetime.now(dt.timezone.utc).date().isoformat(),
        "matrix_file": matrix_metadata.get("matrix_file", runner.config.wstg_matrix_file),
        "osmap_commit": local_git_head(),
        "target_host": runner.config.host,
        "base_url": runner.config.base_url,
        "auth_mode": auth_mode,
        "evidence_path": str(runner.run_dir),
    }


def write_summary(runner: Runner, args: argparse.Namespace, release_errors: list[str]) -> None:
    matrix_metadata = active_matrix_metadata(runner.config)
    data = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": runner.config.base_url,
        "commands": [" ".join(shlex.quote(part) for part in sys.argv)],
        "release_mode": runner.config.release_mode,
        "wstg_source_metadata": wstg_source_metadata(runner, matrix_metadata),
        "active_wstg_matrix": matrix_metadata,
        "standards": runner.mapping["standards"],
        "declared_owasp_top_10_2025_coverage": top10_coverage(runner.mapping),
        "owasp_top_10_2025_coverage": proven_top10_coverage(runner.mapping, runner.results),
        "authenticated_proof": runner.authenticated_proof,
        "release_errors": release_errors,
        "results": [
            {
                "test_id": result.test_id,
                "test_name": result.test_name,
                "status": result.status,
                "message": result.message,
                "evidence": result.evidence,
                "details": result.details,
            }
            for result in runner.results
        ],
        "counts": status_counts(runner.results),
        "mapping_file": str(MAPPING_PATH.relative_to(PACK_ROOT)),
    }
    (runner.run_dir / "summary.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (runner.run_dir / "report.md").write_text(render_markdown_report(runner, data), encoding="utf-8")
    write_coverage_markdown(runner.mapping, PACK_ROOT / "COVERAGE.md", matrix_metadata)


def status_counts(results: list[TestResult]) -> dict[str, int]:
    counts = {STATUS_PASS: 0, STATUS_FAIL: 0, STATUS_WARNING: 0, STATUS_SKIP: 0, STATUS_NA: 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts


def render_markdown_report(runner: Runner, data: dict[str, object]) -> str:
    counts = data["counts"]
    lines = [
        "# OSMAP WSTG Test Report",
        "",
        f"- Target: `{runner.config.base_url}`",
        f"- Generated: `{data['generated_at']}`",
        f"- Mapping: `{data['mapping_file']}`",
        f"- Release mode: `{data['release_mode']}`",
        f"- Results: pass={counts.get(STATUS_PASS, 0)}, fail={counts.get(STATUS_FAIL, 0)}, warning={counts.get(STATUS_WARNING, 0)}, skip={counts.get(STATUS_SKIP, 0)}, not_applicable={counts.get(STATUS_NA, 0)}",
        "",
        "## WSTG Source",
        "",
        f"- Source: `{data['wstg_source_metadata']['source_name']}`",
        f"- Version: `{data['wstg_source_metadata']['source_version']}`",
        f"- URL: `{data['wstg_source_metadata']['source_url']}`",
        f"- Source commit: `{data['wstg_source_metadata']['source_commit'] or 'not applicable'}`",
        f"- Active matrix: `{data['active_wstg_matrix']['matrix_file']}`",
        f"- OSMAP commit: `{data['wstg_source_metadata']['osmap_commit']}`",
        f"- Auth mode: `{data['wstg_source_metadata']['auth_mode']}`",
        f"- Evidence path: `{data['wstg_source_metadata']['evidence_path']}`",
        "",
        "## Commands",
        "",
    ]
    lines.extend(f"- `{cmd}`" for cmd in data["commands"])
    if data.get("release_errors"):
        lines.extend(["", "## Release Errors", ""])
        lines.extend(f"- {escape_md(error)}" for error in data["release_errors"])
    lines.extend(["", "## OWASP Top 10 2025 Coverage", "", "| Category | Name | Passed tests | Failed/skipped | Static-only | Gaps |", "| --- | --- | --- | --- | --- | --- |"])
    coverage = data["owasp_top_10_2025_coverage"]
    for category, name in OWASP_TOP_10_2025.items():
        item = coverage[category]
        tests = ", ".join(f"`{test_id}`" for test_id in item["tests"]) or "none"
        incomplete = ", ".join(f"`{test_id}`" for test_id in item.get("incomplete_tests", [])) or "none"
        static_only = ", ".join(f"`{test_id}`" for test_id in item.get("static_only_tests", [])) or "none"
        gaps = ", ".join(f"`{gap_id}`" for gap_id in item["gaps"]) or "none"
        lines.append(f"| `{category}` | {escape_md(name)} | {tests} | {incomplete} | {static_only} | {gaps} |")
    lines.extend(["", "## Results", "", "| Status | Test ID | Test | Message | Evidence |", "| --- | --- | --- | --- | --- |"])
    for result in runner.results:
        evidence = "<br>".join(f"`{item}`" for item in result.evidence) if result.evidence else ""
        lines.append(
            f"| {result.status} | `{result.test_id}` | {escape_md(result.test_name)} | {escape_md(result.message)} | {evidence} |"
        )
    lines.extend(["", "## Gaps", "", "| Gap ID | Area | Reason |", "| --- | --- | --- |"])
    for gap in runner.mapping.get("gaps", []):
        lines.append(f"| `{gap['gap_id']}` | {escape_md(gap['area'])} | {escape_md(gap['reason'])} |")
    lines.append("")
    return "\n".join(lines)


def write_coverage_markdown(mapping: dict[str, object], path: Path, matrix_metadata: dict[str, object]) -> None:
    disposition_counts = matrix_metadata.get("disposition_counts", {})
    lines = [
        "# OSMAP WSTG, ASVS, And OWASP Top 10 Coverage",
        "",
        "Generated from `wstg-asvs-mapping.json` and the active WSTG due-diligence matrix.",
        "",
        "## Standards",
        "",
        "| Standard | Current repository use |",
        "| --- | --- |",
        "| OWASP WSTG v4.2 | Current implemented matrix and mapped runner tests. |",
        "| OWASP WSTG latest | Required for V3 latest-track due diligence when pinned to an upstream commit. |",
        "| OWASP ASVS 5.0.0 | Control mapping for implemented tests where applicable. |",
        "| Project Top 10 crosswalk | Risk grouping for release-required WSTG tests and explicit gaps. |",
        "",
        "## Active Matrix Summary",
        "",
        "| Item | Count |",
        "| --- | ---: |",
        f"| Active matrix rows | {matrix_metadata.get('scenario_count', 0)} |",
        f"| Automated dispositions | {disposition_counts.get('automated', 0) if isinstance(disposition_counts, dict) else 0} |",
        f"| Manual dispositions | {disposition_counts.get('manual', 0) if isinstance(disposition_counts, dict) else 0} |",
        f"| Not-applicable dispositions | {disposition_counts.get('not_applicable', 0) if isinstance(disposition_counts, dict) else 0} |",
        f"| Covered-by-other-evidence dispositions | {disposition_counts.get('covered_by_other_evidence', 0) if isinstance(disposition_counts, dict) else 0} |",
        f"| Deferred dispositions | {disposition_counts.get('deferred', 0) if isinstance(disposition_counts, dict) else 0} |",
        f"| Blocked dispositions | {disposition_counts.get('blocked', 0) if isinstance(disposition_counts, dict) else 0} |",
        f"| Missing dispositions | {matrix_metadata.get('missing_disposition_count', 0)} |",
        f"| Invalid dispositions | {matrix_metadata.get('invalid_disposition_count', 0)} |",
        "",
        "## OWASP Top 10 2025 Crosswalk",
        "",
        "| Category | Name | Release-required tests | Explicit gaps |",
        "| --- | --- | --- | --- |",
    ]
    coverage = top10_coverage(mapping)
    for category, name in OWASP_TOP_10_2025.items():
        item = coverage[category]
        tests = ", ".join(f"`{test_id}`" for test_id in item["tests"]) or "none"
        gaps = ", ".join(f"`{gap_id}`" for gap_id in item["gaps"]) or "none"
        lines.append(f"| `{category}` | {escape_md(name)} | {tests} | {gaps} |")
    lines.extend([
        "",
        "## Mapped Tests",
        "",
        "| Test ID | Test | WSTG v4.2 | ASVS 5.0.0 | OWASP Top 10 2025 | Type | Release Required | Auth Required | TOTP Required | Safe For Release | Severity |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for item in mapping["tests"]:
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                item["test_id"],
                escape_md(item["test_name"]),
                ", ".join(f"`{x}`" for x in item["wstg"]),
                ", ".join(f"`{x}`" for x in item["asvs"]),
                ", ".join(f"`{x}`" for x in item["owasp_top_10_2025"]),
                ", ".join(item["test_type"]),
                str(item["release_required"]).lower(),
                str(item["requires_authenticated_coverage"]).lower(),
                str(item["requires_totp"]).lower(),
                str(item["safe_for_release"]).lower(),
                item["severity_if_failed"],
            )
        )
    lines.extend(["", "## Explicit Gaps", "", "| Gap ID | Area | WSTG | ASVS | OWASP Top 10 2025 | Reason |", "| --- | --- | --- | --- | --- | --- |"])
    for gap in mapping.get("gaps", []):
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} |".format(
                gap["gap_id"],
                escape_md(gap["area"]),
                ", ".join(f"`{x}`" for x in gap["wstg"]) or "n/a",
                ", ".join(f"`{x}`" for x in gap["asvs"]) or "n/a",
                ", ".join(f"`{x}`" for x in gap.get("owasp_top_10_2025", [])) or "n/a",
                escape_md(gap["reason"]),
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def top10_coverage(mapping: dict[str, object]) -> dict[str, dict[str, list[str]]]:
    coverage = {
        category: {"tests": [], "gaps": []}
        for category in OWASP_TOP_10_2025
    }
    for item in mapping["tests"]:
        if item.get("release_required") is not True or item.get("safe_for_release") is not True:
            continue
        for category in item.get("owasp_top_10_2025", []):
            coverage[category]["tests"].append(item["test_id"])
    for gap in mapping.get("gaps", []):
        for category in gap.get("owasp_top_10_2025", []):
            coverage[category]["gaps"].append(gap["gap_id"])
    return coverage


def proven_top10_coverage(mapping: dict[str, object], results: list[TestResult]) -> dict[str, dict[str, list[str]]]:
    coverage = top10_coverage(mapping)
    for item in coverage.values():
        item["tests"] = []
        item["incomplete_tests"] = []
        item["static_only_tests"] = []
    by_id = {result.test_id: result for result in results}
    for item in mapping["tests"]:
        if item.get("release_required") is not True or item.get("safe_for_release") is not True:
            continue
        test_id = str(item["test_id"])
        result = by_id.get(test_id)
        if result is None:
            status = "missing"
        else:
            status = result.status
        is_static_only = set(item.get("test_type", [])) == {"static review"}
        for category in item.get("owasp_top_10_2025", []):
            if status == STATUS_PASS:
                coverage[category]["tests"].append(test_id)
            else:
                coverage[category]["incomplete_tests"].append(test_id)
            if is_static_only:
                coverage[category]["static_only_tests"].append(test_id)
    return coverage


def escape_md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Override OSMAP_BASE_URL")
    parser.add_argument("--host", help="Override OSMAP_HOST")
    parser.add_argument("--output-dir", help="Override OSMAP_OUTPUT_DIR")
    parser.add_argument("--include-host", action="store_true", help="Run read-only ssh host-assisted tests")
    parser.add_argument("--no-host", action="store_true", help="Disable host-assisted tests")
    parser.add_argument("--authenticated", action="store_true", help="Enable authenticated tests when .env has credentials")
    parser.add_argument("--prompt-auth", action="store_true", help="Prompt locally for password and fresh TOTP codes instead of requiring stored auth secrets")
    parser.add_argument("--auth-email", help="Authenticated test email address, used with --authenticated or --prompt-auth")
    parser.add_argument("--unauthenticated", action="store_true", help="Force credential-gated tests to skip")
    parser.add_argument("--release", action="store_true", help="Fail closed on skipped, incomplete, or missing release-required WSTG coverage")
    parser.add_argument("--test-id", action="append", help="Run one test id; may be repeated")
    return parser.parse_args(argv)


def release_errors(mapping: dict[str, object], results: list[TestResult], runner: Runner, selected: set[str] | None) -> list[str]:
    if not runner.config.release_mode:
        return []
    errors: list[str] = []
    if selected:
        errors.append("release mode must run the full WSTG pack, not selected tests")
    matrix_metadata = active_matrix_metadata(runner.config)
    if matrix_metadata.get("missing_disposition_count"):
        errors.append("active WSTG matrix has rows without a release disposition")
    if matrix_metadata.get("invalid_disposition_count"):
        errors.append("active WSTG matrix has rows with invalid release dispositions")
    if runner.config.wstg_source_version.lower() == "latest" and not runner.config.wstg_source_commit:
        errors.append("latest-track WSTG release evidence must include OSMAP_WSTG_SOURCE_COMMIT")
    by_id = {result.test_id: result for result in results}
    for item in mapping["tests"]:
        test_id = item["test_id"]
        if item.get("release_required") is not True:
            continue
        result = by_id.get(test_id)
        if result is None:
            errors.append(f"{test_id} missing from release run")
            continue
        if result.status != STATUS_PASS:
            errors.append(f"{test_id} has release-blocking status {result.status}")
        if item.get("requires_authenticated_coverage") is True:
            if "authenticated" not in item.get("test_type", []):
                errors.append(f"{test_id} requires authenticated coverage but is not typed authenticated")
            if item.get("requires_totp") is not True:
                errors.append(f"{test_id} requires authenticated coverage without TOTP metadata")
    errors.extend(runner.finalize_release_authentication_proof())
    return errors


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    config = build_config(args)
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = config.output_dir / f"osmap-wstg-{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    runner = Runner(config, mapping, run_dir)
    print(f"Run directory: {run_dir}")
    selected = set(args.test_id) if args.test_id else None
    results = runner.run(selected)
    errors = release_errors(mapping, results, runner, selected)
    write_summary(runner, args, errors)
    print(f"Summary: {run_dir / 'summary.json'}")
    print(f"Report:  {run_dir / 'report.md'}")
    if errors:
        for error in errors:
            print(f"RELEASE-ERROR {error}", file=sys.stderr)
    return 1 if errors or any(result.status == STATUS_FAIL for result in runner.results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
