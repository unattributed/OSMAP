#!/usr/bin/env python3
"""Evidence-producing OWASP WSTG v4.2 runner for the OSMAP browser surface."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
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
DEFAULT_BODY_LIMIT = 256 * 1024
SECRET_REPLACEMENT = "[REDACTED]"


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
            "OSMAP-WSTG-ATHN-001": self.test_login_form,
            "OSMAP-WSTG-ATHN-002": self.test_invalid_login,
            "OSMAP-WSTG-ATHN-003": self.test_throttle_probe,
            "OSMAP-WSTG-ATHN-004": self.test_authenticated_login,
            "OSMAP-WSTG-SESS-001": self.test_session_cookie_flags,
            "OSMAP-WSTG-SESS-002": self.test_session_fixation,
            "OSMAP-WSTG-SESS-003": self.test_logout_csrf,
            "OSMAP-WSTG-SESS-004": self.test_authenticated_csrf,
            "OSMAP-WSTG-SESS-005": self.test_authenticated_cache_control,
            "OSMAP-WSTG-CONF-004": self.test_methods,
            "OSMAP-WSTG-INFO-001": self.test_metafiles,
            "OSMAP-WSTG-INFO-002": self.test_info_disclosure,
            "OSMAP-WSTG-INPV-001": self.test_path_traversal,
            "OSMAP-WSTG-INPV-002": self.test_reflected_input,
            "OSMAP-WSTG-CLNT-001": self.test_cors,
            "OSMAP-WSTG-CLNT-002": self.test_html_rendering_static,
            "OSMAP-WSTG-BUSL-001": self.test_attachment_static,
            "OSMAP-WSTG-CONF-005": self.test_host_bindings,
            "OSMAP-WSTG-CONF-006": self.test_host_pf,
            "OSMAP-WSTG-CONF-007": self.test_dependency_alignment,
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
                context = ssl.create_default_context()
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    host, port=port, timeout=self.config.timeout, context=context
                )
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=self.config.timeout)
            conn.request(method, path, body=body_bytes, headers=headers)
            response = conn.getresponse()
            body_data = response.read(DEFAULT_BODY_LIMIT)
            evidence = HttpEvidence(
                label=label,
                status=response.status,
                reason=response.reason,
                headers=response.getheaders(),
                body=body_data,
            )
            if store_cookies:
                self.store_response_cookies(evidence)
            conn.close()
        except (OSError, ssl.SSLError, socket.timeout) as exc:
            evidence = HttpEvidence(label, None, "", [], b"", error=str(exc))
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
        )

    def write_http_evidence(self, evidence: HttpEvidence) -> None:
        stem = safe_label(evidence.label)
        headers_path = self.evidence_dir / f"{stem}.headers"
        body_path = self.evidence_dir / f"{stem}.body"
        lines = []
        if evidence.status is None:
            lines.append(f"ERROR: {self.redact(evidence.error)}\n")
        else:
            lines.append(f"HTTP {evidence.status} {evidence.reason}\n")
            for key, value in evidence.headers:
                if key.lower() in {"set-cookie", "cookie", "authorization"}:
                    value = SECRET_REPLACEMENT
                lines.append(f"{key}: {self.redact(value)}\n")
        headers_path.write_text("".join(lines), encoding="utf-8")
        body_path.write_text(self.redact(evidence.body_text()), encoding="utf-8")

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
            return generate_totp(self.config.totp_secret)
        prompt = f"Current TOTP for {self.config.test_email} ({reason}): "
        code = getpass.getpass(prompt).strip().replace(" ", "")
        if code:
            self.secrets.append(code)
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
        mailboxes = self.request(
            "auth_mailboxes",
            "GET",
            "/mailboxes",
            cookies=self.cookie_jar,
        )
        if mailboxes.status != 200:
            return False, f"mailbox check failed with HTTP {mailboxes.status}"
        self.csrf_token = extract_csrf(mailboxes.body_text())
        self.authenticated = True
        return True, "authenticated"

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
        for attempt in range(1, self.config.throttle_attempts + 1):
            evidence = self.form_post(
                f"throttle_probe_attempt_{attempt}",
                "/login",
                {
                    "username": "wstg-throttle@example.invalid",
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

    def test_path_traversal(self) -> TestResult:
        probes = {
            "path_traversal_dotdot": "/mailboxes/../login",
            "path_traversal_encoded": "/mailboxes/%2e%2e/login",
            "path_traversal_attachment": "/attachment?mailbox=..%2f..%2fetc&uid=1&part=1",
        }
        bad: dict[str, int | None] = {}
        evidence_paths: list[str] = []
        for label, path in probes.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.extend([f"evidence/{label}.headers", f"evidence/{label}.body"])
            body = evidence.body_text().lower()
            if evidence.status == 200 or "root:" in body or "osmap_session" in body:
                bad[label] = evidence.status
        if bad:
            return self.result("OSMAP-WSTG-INPV-001", STATUS_FAIL, "path traversal probe reached sensitive-looking content or succeeded", evidence_paths, {"bad": bad})
        return self.result("OSMAP-WSTG-INPV-001", STATUS_PASS, "path traversal probes were rejected or safely gated", evidence_paths)

    def test_reflected_input(self) -> TestResult:
        payload = "<script>alert(1)</script>"
        encoded = urllib.parse.quote(payload, safe="")
        probes = {
            "reflected_input_login": f"/login?probe={encoded}",
            "reflected_input_search": f"/search?q={encoded}",
            "reflected_input_mailbox": f"/mailbox?name={encoded}",
        }
        bad: list[str] = []
        evidence_paths: list[str] = []
        for label, path in probes.items():
            evidence = self.request(label, "GET", path)
            evidence_paths.append(f"evidence/{label}.body")
            if payload in evidence.body_text() or "<script>alert(1)</script>" in evidence.body_text().lower():
                bad.append(label)
        if bad:
            return self.result("OSMAP-WSTG-INPV-002", STATUS_FAIL, "probe payload was reflected as raw script markup", evidence_paths, {"bad": bad})
        return self.result("OSMAP-WSTG-INPV-002", STATUS_PASS, "probe payloads were not reflected as executable markup", evidence_paths)

    def test_cors(self) -> TestResult:
        bad: dict[str, dict[str, str]] = {}
        evidence_paths: list[str] = []
        for origin in ["https://attacker.invalid", "null"]:
            label = f"cors_{origin.replace(':', '_').replace('/', '_')}"
            evidence = self.request(label, "GET", "/login", headers={"Origin": origin})
            evidence_paths.append(f"evidence/{safe_label(label)}.headers")
            acao = evidence.first_header("Access-Control-Allow-Origin")
            acac = evidence.first_header("Access-Control-Allow-Credentials")
            if acao == origin and acac.lower() == "true":
                bad[origin] = {"acao": acao, "acac": acac}
        if bad:
            return self.result("OSMAP-WSTG-CLNT-001", STATUS_FAIL, "credentialed cross-origin CORS was allowed", evidence_paths, {"bad": bad})
        return self.result("OSMAP-WSTG-CLNT-001", STATUS_PASS, "cross-origin probes did not receive permissive credentialed CORS", evidence_paths)

    def test_html_rendering_static(self) -> TestResult:
        files = [
            REPO_ROOT / "src" / "rendering.rs",
            REPO_ROOT / "src" / "rendering_html.rs",
            REPO_ROOT / "src" / "http_support.rs",
            REPO_ROOT / "docs" / "RENDERING_POLICY_BASELINE.md",
        ]
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files if path.exists())
        markers = ["sanitize", "escape_html", "default-src 'none'", "external", "script"]
        missing = [marker for marker in markers if marker.lower() not in text.lower()]
        evidence = self.write_text_evidence("static_html_rendering.txt", summarize_static_files(files, missing))
        if missing:
            return self.result("OSMAP-WSTG-CLNT-002", STATUS_FAIL, "HTML rendering policy markers were missing from source/docs", [evidence], {"missing": missing})
        return self.result("OSMAP-WSTG-CLNT-002", STATUS_PASS, "source and docs align with conservative HTML rendering policy", [evidence])

    def test_attachment_static(self) -> TestResult:
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
        evidence = self.write_text_evidence("static_attachment_handling.txt", summarize_static_files(files, missing))
        if missing:
            return self.result("OSMAP-WSTG-BUSL-001", STATUS_FAIL, "attachment handling markers were missing from source/docs", [evidence], {"missing": missing})
        return self.result("OSMAP-WSTG-BUSL-001", STATUS_PASS, "source and docs show bounded upload parsing and forced-download controls", [evidence])

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
        if missing_files:
            return self.result("OSMAP-WSTG-CONF-007", STATUS_FAIL, "dependency alignment files are missing", [evidence], {"missing": missing_files})
        return self.result("OSMAP-WSTG-CONF-007", STATUS_PASS, "lockfile and supply-chain security documentation/tooling are present", [evidence])

    def run_ssh(self, filename: str, command: str) -> str:
        try:
            completed = subprocess.run(
                ["ssh", self.config.ssh_host, command],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=max(20, int(self.config.timeout) + 10),
            )
            output = completed.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = f"ERROR: {exc}\n"
        self.write_text_evidence(filename, output)
        return output


def same_origin_headers(config: Config) -> dict[str, str]:
    return {"Origin": f"{config.scheme}://{config.host}", "Referer": f"{config.base_url}/mailboxes"}


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
    return Config(
        base_url=base_url.rstrip("/"),
        host=host,
        ssh_host=merged.get("OSMAP_SSH_HOST", "mail"),
        test_email=args.auth_email or merged.get("OSMAP_TEST_EMAIL", ""),
        test_password=merged.get("OSMAP_TEST_PASSWORD", ""),
        totp_secret=merged.get("OSMAP_TOTP_SECRET", ""),
        secondary_email=merged.get("OSMAP_SECONDARY_EMAIL", ""),
        output_dir=output_root,
        rate_delay=float(merged.get("OSMAP_RATE_LIMIT_DELAY_SECONDS", "1") or "1"),
        allow_authenticated=allow_auth,
        prompt_auth=prompt_auth,
        allow_host_assisted=allow_host,
        throttle_attempts=max(1, int(merged.get("OSMAP_THROTTLE_PROBE_ATTEMPTS", "3") or "3")),
        timeout=float(merged.get("OSMAP_REQUEST_TIMEOUT_SECONDS", "12") or "12"),
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


def write_summary(runner: Runner, args: argparse.Namespace) -> None:
    data = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": runner.config.base_url,
        "commands": [" ".join(shlex.quote(part) for part in sys.argv)],
        "standards": runner.mapping["standards"],
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
    write_coverage_markdown(runner.mapping, PACK_ROOT / "COVERAGE.md")


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
        f"- Results: pass={counts.get(STATUS_PASS, 0)}, fail={counts.get(STATUS_FAIL, 0)}, warning={counts.get(STATUS_WARNING, 0)}, skip={counts.get(STATUS_SKIP, 0)}, not_applicable={counts.get(STATUS_NA, 0)}",
        "",
        "## Commands",
        "",
    ]
    lines.extend(f"- `{cmd}`" for cmd in data["commands"])
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


def write_coverage_markdown(mapping: dict[str, object], path: Path) -> None:
    lines = [
        "# OSMAP WSTG and ASVS Coverage",
        "",
        "Generated from `wstg-asvs-mapping.json`.",
        "",
        "| Test ID | Test | WSTG v4.2 | ASVS 5.0.0 | Type | Severity |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in mapping["tests"]:
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} |".format(
                item["test_id"],
                escape_md(item["test_name"]),
                ", ".join(f"`{x}`" for x in item["wstg"]),
                ", ".join(f"`{x}`" for x in item["asvs"]),
                ", ".join(item["test_type"]),
                item["severity_if_failed"],
            )
        )
    lines.extend(["", "## Explicit Gaps", "", "| Gap ID | Area | WSTG | ASVS | Reason |", "| --- | --- | --- | --- | --- |"])
    for gap in mapping.get("gaps", []):
        lines.append(
            "| `{}` | {} | {} | {} | {} |".format(
                gap["gap_id"],
                escape_md(gap["area"]),
                ", ".join(f"`{x}`" for x in gap["wstg"]) or "n/a",
                ", ".join(f"`{x}`" for x in gap["asvs"]) or "n/a",
                escape_md(gap["reason"]),
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    parser.add_argument("--test-id", action="append", help="Run one test id; may be repeated")
    return parser.parse_args(argv)


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
    runner.run(selected)
    write_summary(runner, args)
    print(f"Summary: {run_dir / 'summary.json'}")
    print(f"Report:  {run_dir / 'report.md'}")
    return 1 if any(result.status == STATUS_FAIL for result in runner.results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
