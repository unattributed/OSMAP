#!/usr/bin/env python3
"""Evidence-producing MITRE ATT&CK and OWASP Top 10 border checks for OSMAP."""

from __future__ import annotations

import argparse
import datetime as dt
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

PACK_ROOT = Path(__file__).resolve().parent
OSMAP_ROOT = PACK_ROOT.parents[1]
WORKSPACE_ROOT = OSMAP_ROOT.parent
MAILSTACK_ROOT = WORKSPACE_ROOT / "openbsd-mailstack"
MAPPING_PATH = PACK_ROOT / "mitre-owasp-border-mapping.json"
DEFAULT_BODY_LIMIT = 128 * 1024
SECRET_REPLACEMENT = "[REDACTED]"


def osmap_tls_client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


@dataclass
class Config:
    base_url: str
    host: str
    ssh_host: str
    output_dir: Path
    rate_delay: float
    timeout: float
    allow_host_assisted: bool

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

    def first_header(self, name: str) -> str:
        needle = name.lower()
        for key, value in self.headers:
            if key.lower() == needle:
                return value
        return ""

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
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[TestResult] = []

    def run(self, selected_ids: set[str] | None = None) -> list[TestResult]:
        tests: dict[str, Callable[[], TestResult]] = {
            "OSMAP-BORDER-WEB-001": self.test_web_protocol_boundary,
            "OSMAP-BORDER-WEB-002": self.test_suspicious_endpoint_exposure,
            "OSMAP-BORDER-WEB-003": self.test_control_plane_public_exposure,
            "OSMAP-BORDER-WEB-004": self.test_spoofed_proxy_headers,
            "OSMAP-BORDER-WEB-005": self.test_host_header_boundary,
            "OSMAP-BORDER-WEB-006": self.test_injection_diagnostics,
            "OSMAP-BORDER-WEB-007": self.test_ssrf_parameter_probes,
            "OSMAP-BORDER-NET-001": self.test_public_tcp_exposure,
            "OSMAP-BORDER-HOST-001": self.test_host_service_state,
            "OSMAP-BORDER-HOST-002": self.test_host_binding_exposure,
            "OSMAP-BORDER-HOST-003": self.test_pf_suricata_posture,
            "OSMAP-BORDER-HOST-004": self.test_nginx_route_split,
            "OSMAP-BORDER-LOG-001": self.test_purple_team_logging_marker,
            "OSMAP-BORDER-REPO-001": self.test_mailstack_repo_alignment,
        }
        for item in self.mapping["tests"]:
            test_id = item["test_id"]
            if selected_ids and test_id not in selected_ids:
                continue
            try:
                result = tests[test_id]()
            except Exception as exc:  # noqa: BLE001 - report crashes as test failures.
                result = self.result(
                    test_id,
                    STATUS_FAIL,
                    f"test raised unexpected error: {exc}",
                    details={"exception_type": type(exc).__name__},
                )
            self.results.append(result)
            print(f"{result.status.upper():15} {result.test_id} {result.message}")
            time.sleep(self.config.rate_delay)
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
        headers: dict[str, str] | None = None,
        host_header: str | None = None,
        scheme: str | None = None,
        port: int | None = None,
    ) -> HttpEvidence:
        scheme = scheme or self.config.scheme
        port = port or (443 if scheme == "https" else 80)
        merged = dict(headers or {})
        merged.setdefault("Host", host_header or self.config.host)
        merged.setdefault("User-Agent", "osmap-border-pack/1.0")
        evidence = HttpEvidence(label, None, "", [], b"")
        try:
            if scheme == "https":
                context = osmap_tls_client_context()
                conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                    self.config.host,
                    port=port,
                    timeout=self.config.timeout,
                    context=context,
                )
            else:
                conn = http.client.HTTPConnection(self.config.host, port=port, timeout=self.config.timeout)
            conn.request(method, path, headers=merged)
            response = conn.getresponse()
            evidence = HttpEvidence(label, response.status, response.reason, response.getheaders(), response.read(DEFAULT_BODY_LIMIT))
            conn.close()
        except (OSError, ssl.SSLError, socket.timeout, http.client.HTTPException) as exc:
            evidence = HttpEvidence(label, None, "", [], b"", error=str(exc))
        self.write_http_evidence(evidence)
        return evidence

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
        redacted = re.sub(r"(?i)(authorization:\s*)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
        redacted = re.sub(r"(?i)(cookie:\s*).+", r"\1[REDACTED]", redacted)
        redacted = re.sub(r"(?i)(set-cookie:\s*).+", r"\1[REDACTED]", redacted)
        return redacted

    def run_ssh(self, label: str, command: str) -> str:
        if not self.config.allow_host_assisted:
            output = "SKIP: host-assisted tests disabled\n"
            self.write_text_evidence(label, output)
            return output
        try:
            completed = subprocess.run(
                ["ssh", self.config.ssh_host, command],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=max(25, int(self.config.timeout) + 15),
            )
            output = completed.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = f"ERROR: {exc}\n"
        self.write_text_evidence(label, output)
        return output

    def test_web_protocol_boundary(self) -> TestResult:
        login = self.request("web_boundary_login", "GET", "/login")
        tls = tls_handshake(self.config.host, self.config.port, self.config.timeout)
        tls_evidence = self.write_text_evidence("web_boundary_tls.txt", json.dumps(tls, indent=2, sort_keys=True))
        tests = [
            self.request("web_boundary_options", "OPTIONS", "/login"),
            self.request("web_boundary_trace", "TRACE", "/login"),
            self.request("web_boundary_connect", "CONNECT", "/login"),
        ]
        evidence = ["evidence/web_boundary_login.headers", tls_evidence] + [f"evidence/{safe_label(item.label)}.headers" for item in tests]
        if login.status != 200:
            return self.result("OSMAP-BORDER-WEB-001", STATUS_FAIL, f"HTTPS /login did not return 200 (got {login.status or login.error})", evidence)
        if tls.get("status") != "ok" or tls.get("version") not in {"TLSv1.2", "TLSv1.3"}:
            return self.result("OSMAP-BORDER-WEB-001", STATUS_FAIL, "TLS handshake did not negotiate TLS 1.2 or TLS 1.3", evidence, tls)
        accepted = [item.label for item in tests if item.status and item.status < 400]
        if accepted:
            return self.result("OSMAP-BORDER-WEB-001", STATUS_FAIL, "unsafe or tunnel-style methods were accepted", evidence, {"accepted": accepted})
        return self.result("OSMAP-BORDER-WEB-001", STATUS_PASS, "HTTPS edge is reachable and unsafe methods are rejected", evidence)

    def test_suspicious_endpoint_exposure(self) -> TestResult:
        paths = [
            "/.env",
            "/wp-login.php",
            "/shell.php",
            "/cmd.php",
            "/gate.php",
            "/beacon",
            "/api/v1/agent/checkin",
            "/actuator/env",
            "/server-status",
            "/debug/vars",
            "/.git/config",
        ]
        responses = [self.request(f"suspicious_path_{index}", "GET", path) for index, path in enumerate(paths, 1)]
        exposed = [paths[index] for index, item in enumerate(responses) if item.status == 200 and suspicious_body(item.body_text())]
        evidence = [f"evidence/{safe_label(item.label)}.headers" for item in responses]
        if exposed:
            return self.result("OSMAP-BORDER-WEB-002", STATUS_FAIL, "suspicious public paths exposed useful content", evidence, {"exposed": exposed})
        return self.result("OSMAP-BORDER-WEB-002", STATUS_PASS, "suspicious webshell, C2, and diagnostics paths did not expose useful handlers", evidence)

    def test_control_plane_public_exposure(self) -> TestResult:
        paths = control_plane_paths()
        responses = [self.request(f"control_plane_{index}", "GET", path) for index, path in enumerate(paths, 1)]
        exposed = [paths[index] for index, item in enumerate(responses) if public_content_exposed(item)]
        evidence = [f"evidence/{safe_label(item.label)}.headers" for item in responses]
        if exposed:
            return self.result("OSMAP-BORDER-WEB-003", STATUS_FAIL, "control-plane paths exposed public content", evidence, {"exposed": exposed})
        return self.result("OSMAP-BORDER-WEB-003", STATUS_PASS, "adjacent control-plane paths are not publicly exposed", evidence)

    def test_spoofed_proxy_headers(self) -> TestResult:
        headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "Forwarded": "for=127.0.0.1;proto=https;host=mail.blackbagsecurity.com",
            "X-Original-URL": "/postfixadmin/",
            "X-Rewrite-URL": "/postfixadmin/",
        }
        paths = ["/postfixadmin/", "/rspamd/", "/stub_status", "/_ops/monitor/"]
        responses = [self.request(f"spoofed_headers_{index}", "GET", path, headers=headers) for index, path in enumerate(paths, 1)]
        exposed = [paths[index] for index, item in enumerate(responses) if public_content_exposed(item)]
        evidence = [f"evidence/{safe_label(item.label)}.headers" for item in responses]
        if exposed:
            return self.result("OSMAP-BORDER-WEB-004", STATUS_FAIL, "spoofed forwarding headers unlocked private paths", evidence, {"exposed": exposed})
        return self.result("OSMAP-BORDER-WEB-004", STATUS_PASS, "spoofed forwarding headers did not bypass public route controls", evidence)

    def test_host_header_boundary(self) -> TestResult:
        response = self.request("host_header_attacker_invalid", "GET", "/login", host_header="attacker.invalid")
        evidence = ["evidence/host_header_attacker_invalid.headers", "evidence/host_header_attacker_invalid.body"]
        body = response.body_text().lower()
        if response.status == 200 and ("name=\"password\"" in body or "osmap" in body):
            return self.result("OSMAP-BORDER-WEB-005", STATUS_FAIL, "unexpected Host header served OSMAP login content", evidence)
        if response.status is None:
            return self.result("OSMAP-BORDER-WEB-005", STATUS_WARNING, "unexpected Host header probe did not complete", evidence)
        return self.result("OSMAP-BORDER-WEB-005", STATUS_PASS, "unexpected Host header did not serve OSMAP login content", evidence)

    def test_injection_diagnostics(self) -> TestResult:
        paths = [
            "/login?username=%27%20OR%201%3D1--",
            "/mailboxes?mailbox=%27%20OR%201%3D1--",
            "/message?uid=../../../../etc/passwd",
            "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        ]
        responses = [self.request(f"injection_diag_{index}", "GET", path) for index, path in enumerate(paths, 1)]
        leaks = [paths[index] for index, item in enumerate(responses) if diagnostic_leak(item.body_text())]
        evidence = [f"evidence/{safe_label(item.label)}.body" for item in responses]
        if leaks:
            return self.result("OSMAP-BORDER-WEB-006", STATUS_FAIL, "injection-shaped probes exposed backend diagnostics", evidence, {"leaks": leaks})
        return self.result("OSMAP-BORDER-WEB-006", STATUS_PASS, "injection-shaped probes did not expose backend diagnostics", evidence)

    def test_ssrf_parameter_probes(self) -> TestResult:
        paths = [
            "/login?url=http://127.0.0.1:8080/",
            "/login?next=http://169.254.169.254/latest/meta-data/",
            "/mailboxes?redirect=http://127.0.0.1:11334/",
            "/mailboxes?avatar=file:///etc/passwd",
        ]
        responses = [self.request(f"ssrf_probe_{index}", "GET", path) for index, path in enumerate(paths, 1)]
        leaks = [paths[index] for index, item in enumerate(responses) if internal_content_leak(item.body_text()) or diagnostic_leak(item.body_text())]
        evidence = [f"evidence/{safe_label(item.label)}.body" for item in responses]
        if leaks:
            return self.result("OSMAP-BORDER-WEB-007", STATUS_FAIL, "SSRF-shaped parameters returned internal content or diagnostics", evidence, {"leaks": leaks})
        return self.result("OSMAP-BORDER-WEB-007", STATUS_PASS, "SSRF-shaped parameters did not return internal service content", evidence)

    def test_public_tcp_exposure(self) -> TestResult:
        expected_or_documented = {22, 25, 80, 443}
        high_risk = {3306, 5432, 6379, 8080, 8443, 9000, 9090, 11332, 11333, 11334}
        observed: dict[str, str] = {}
        for port in sorted(expected_or_documented | high_risk | {110, 143, 465, 587, 993, 995}):
            observed[str(port)] = tcp_state(self.config.host, port, self.config.timeout)
        evidence = self.write_text_evidence("public_tcp_exposure.txt", json.dumps(observed, indent=2, sort_keys=True))
        exposed_high_risk = [port for port in high_risk if observed[str(port)] == "open"]
        if exposed_high_risk:
            return self.result("OSMAP-BORDER-NET-001", STATUS_FAIL, "high-risk backend ports are reachable from the public internet", [evidence], {"open_high_risk_ports": exposed_high_risk})
        return self.result("OSMAP-BORDER-NET-001", STATUS_PASS, "public TCP exposure is bounded; high-risk backend ports are not reachable", [evidence], {"observed": observed})

    def test_host_service_state(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-BORDER-HOST-001", STATUS_SKIP, "host-assisted tests disabled")
        output = self.run_ssh(
            "host_service_state.txt",
            "hostname; for svc in nginx osmap_serve osmap_mailbox_helper postfix dovecot rspamd suricata; do rcctl check \"$svc\" 2>&1 || true; done",
        )
        required = ["nginx(ok)", "osmap_serve(ok)", "osmap_mailbox_helper(ok)", "postfix(ok)", "dovecot(ok)", "rspamd(ok)"]
        missing = [item for item in required if item not in output]
        evidence = ["evidence/host_service_state.txt"]
        if "ERROR:" in output:
            return self.result("OSMAP-BORDER-HOST-001", STATUS_WARNING, "host service state evidence was unavailable", evidence)
        if missing:
            return self.result("OSMAP-BORDER-HOST-001", STATUS_FAIL, "required host services are not healthy", evidence, {"missing": missing})
        if "suricata(ok)" not in output:
            return self.result("OSMAP-BORDER-HOST-001", STATUS_WARNING, "core services are healthy but Suricata is not reported as running", evidence)
        return self.result("OSMAP-BORDER-HOST-001", STATUS_PASS, "core web, OSMAP, mail, filtering, and IDS services are healthy", evidence)

    def test_host_binding_exposure(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-BORDER-HOST-002", STATUS_SKIP, "host-assisted tests disabled")
        output = self.run_ssh(
            "host_binding_exposure.txt",
            "netstat -an -f inet | egrep 'LISTEN' | sort",
        )
        evidence = ["evidence/host_binding_exposure.txt"]
        if "ERROR:" in output:
            return self.result("OSMAP-BORDER-HOST-002", STATUS_WARNING, "host binding evidence was unavailable", evidence)
        public_backend = []
        for line in output.splitlines():
            if re.search(r"(\\*|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\\.(8080|11332|11333|11334|3306|6379)\\s", line) and not any(
                safe in line for safe in ("127.0.0.1.", "10.44.0.1.")
            ):
                public_backend.append(line)
        if public_backend:
            return self.result("OSMAP-BORDER-HOST-002", STATUS_FAIL, "backend service bindings are exposed outside loopback or VPN", evidence, {"public_backend": public_backend})
        return self.result("OSMAP-BORDER-HOST-002", STATUS_PASS, "backend bindings are loopback or VPN scoped", evidence)

    def test_pf_suricata_posture(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-BORDER-HOST-003", STATUS_SKIP, "host-assisted tests disabled")
        output = self.run_ssh(
            "host_pf_suricata.txt",
            "doas pfctl -s info 2>/dev/null | head -30; printf '\\n--- rules ---\\n'; doas pfctl -sr 2>/dev/null | head -120; printf '\\n--- tables ---\\n'; doas pfctl -s Tables 2>/dev/null | egrep 'suricata|sshguard|blocked_smtp|smtp_abuse' || true; printf '\\n--- suricata files ---\\n'; ls -l /etc/suricata /var/log/suricata 2>/dev/null || true",
        )
        evidence = ["evidence/host_pf_suricata.txt"]
        if "ERROR:" in output:
            return self.result("OSMAP-BORDER-HOST-003", STATUS_WARNING, "pf and Suricata evidence was unavailable", evidence)
        if "Status: Enabled" not in output or "block drop" not in output:
            return self.result("OSMAP-BORDER-HOST-003", STATUS_FAIL, "pf is not enabled with visible default-drop posture", evidence)
        if "suricata" not in output.lower():
            return self.result("OSMAP-BORDER-HOST-003", STATUS_WARNING, "pf is enabled but Suricata artifacts were not visible", evidence)
        return self.result("OSMAP-BORDER-HOST-003", STATUS_PASS, "pf default-drop and Suricata/PF artifacts are visible", evidence)

    def test_nginx_route_split(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-BORDER-HOST-004", STATUS_SKIP, "host-assisted tests disabled")
        output = self.run_ssh(
            "host_nginx_route_split.txt",
            "doas nginx -T 2>/dev/null | egrep 'server_name mail.blackbagsecurity.com|include /etc/nginx/templates/osmap-root.tmpl|include /etc/nginx/templates/control-plane-allow.tmpl|location /postfixadmin/|location /rspamd/|location = /stub_status|proxy_pass http://127.0.0.1:8080|roundcube.tmpl' | head -160",
        )
        evidence = ["evidence/host_nginx_route_split.txt"]
        if "ERROR:" in output:
            return self.result("OSMAP-BORDER-HOST-004", STATUS_WARNING, "nginx route split evidence was unavailable", evidence)
        required = ["server_name mail.blackbagsecurity.com", "include /etc/nginx/templates/osmap-root.tmpl", "proxy_pass http://127.0.0.1:8080", "control-plane-allow.tmpl"]
        missing = [item for item in required if item not in output]
        if missing:
            return self.result("OSMAP-BORDER-HOST-004", STATUS_FAIL, "nginx route split evidence is missing expected markers", evidence, {"missing": missing})
        if "roundcube.tmpl" in output:
            return self.result("OSMAP-BORDER-HOST-004", STATUS_WARNING, "nginx output still references roundcube template; verify it is private-only", evidence)
        return self.result("OSMAP-BORDER-HOST-004", STATUS_PASS, "nginx evidence shows OSMAP route and private control-plane split markers", evidence)

    def test_purple_team_logging_marker(self) -> TestResult:
        if not self.config.allow_host_assisted:
            return self.result("OSMAP-BORDER-LOG-001", STATUS_SKIP, "host-assisted tests disabled")
        marker = "osmap-border-" + dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%S")
        path = f"/__osmap_border_probe__?marker={urllib.parse.quote(marker)}"
        self.request(
            "purple_team_marker_request",
            "GET",
            path,
            headers={"User-Agent": f"osmap-border-purple-team/1.0 marker-{marker}", "X-OSMAP-Border-Test": marker},
        )
        time.sleep(2)
        quoted = shlex.quote(marker)
        output = self.run_ssh(
            "purple_team_logging_marker.txt",
            "printf 'marker=%s\\n' "
            + quoted
            + "; printf '\\n--- nginx access ---\\n'; doas grep -F "
            + quoted
            + " /var/log/nginx/osmap.public.access.log 2>/dev/null | tail -5 || true; printf '\\n--- nginx error ---\\n'; doas grep -F "
            + quoted
            + " /var/log/nginx/osmap.public.error.log 2>/dev/null | tail -5 || true; printf '\\n--- suricata eve ---\\n'; doas grep -F "
            + quoted
            + " /var/log/suricata/eve.json 2>/dev/null | tail -5 || true",
        )
        evidence = ["evidence/purple_team_marker_request.headers", "evidence/purple_team_logging_marker.txt"]
        if "ERROR:" in output:
            return self.result("OSMAP-BORDER-LOG-001", STATUS_WARNING, "backend log correlation evidence was unavailable", evidence)
        if marker not in output:
            return self.result("OSMAP-BORDER-LOG-001", STATUS_FAIL, "backend logs did not contain the benign border-test marker", evidence, {"marker": marker})
        if "--- nginx access ---" in output and "/__osmap_border_probe__" in output:
            return self.result("OSMAP-BORDER-LOG-001", STATUS_PASS, "backend nginx access logs captured the benign border-test marker", evidence, {"marker": marker})
        return self.result("OSMAP-BORDER-LOG-001", STATUS_WARNING, "marker was found, but expected nginx access log line was not confirmed", evidence, {"marker": marker})

    def test_mailstack_repo_alignment(self) -> TestResult:
        required = [
            MAILSTACK_ROOT / "services" / "nginx" / "etc" / "nginx" / "templates" / "control-plane-allow.tmpl",
            MAILSTACK_ROOT / "services" / "firewall" / "etc" / "pf.conf.template",
            MAILSTACK_ROOT / "services" / "suricata" / "etc" / "suricata" / "suricata.yaml.template",
            MAILSTACK_ROOT / "services" / "rspamd" / "README.md",
            MAILSTACK_ROOT / "services" / "postfix" / "README.md",
            MAILSTACK_ROOT / "services" / "dovecot" / "README.md",
            MAILSTACK_ROOT / "services" / "sbom" / "README.md",
            MAILSTACK_ROOT / "maint" / "validate-public-hardening-surface.ksh",
            MAILSTACK_ROOT / "maint" / "sbom-daily-scan.ksh",
            MAILSTACK_ROOT / "scripts" / "ops" / "suricata-dump.ksh",
            MAILSTACK_ROOT / "scripts" / "ops" / "suricata-eve2pf.ksh",
        ]
        lines = ["Checked backend mailstack security alignment files:"]
        missing = []
        for path in required:
            rel = path.relative_to(MAILSTACK_ROOT) if path.is_relative_to(MAILSTACK_ROOT) else path
            state = "present" if path.exists() else "missing"
            lines.append(f"- {rel}: {state}")
            if not path.exists():
                missing.append(str(rel))
        nginx_template = MAILSTACK_ROOT / "services" / "nginx" / "etc" / "nginx" / "sites-available" / "main-ssl.conf.template"
        if nginx_template.exists():
            template_text = nginx_template.read_text(encoding="utf-8", errors="replace")
            if "return 421;" not in template_text or "$host !~" not in template_text:
                missing.append("services/nginx/etc/nginx/sites-available/main-ssl.conf.template host-header 421 guard")
                lines.append("- nginx main-ssl host-header 421 guard: missing")
            else:
                lines.append("- nginx main-ssl host-header 421 guard: present")
        evidence = self.write_text_evidence("mailstack_repo_alignment.txt", "\n".join(lines) + "\n")
        if missing:
            return self.result("OSMAP-BORDER-REPO-001", STATUS_FAIL, "backend mailstack hardening or monitoring assets are missing", [evidence], {"missing": missing})
        return self.result("OSMAP-BORDER-REPO-001", STATUS_PASS, "backend mailstack hardening, SBOM, PF, and IDS assets are present", [evidence])


def control_plane_paths() -> list[str]:
    return [
        "/postfixadmin/",
        "/postfixadmin/setup.php",
        "/postfixadmin/upgrade.php",
        "/rspamd/",
        "/sogo/",
        "/SOGo/",
        "/stub_status",
        "/_ops/monitor/",
        "/_ops/monitor/data/",
        "/pf/",
        "/dr/",
        "/roundcube/",
        "/phpmyadmin/",
    ]


def public_content_exposed(evidence: HttpEvidence) -> bool:
    if evidence.status != 200:
        return False
    body = evidence.body_text().lower()
    exposed_markers = [
        "postfix admin",
        "rspamd",
        "sogo",
        "active connections",
        "roundcube",
        "phpmyadmin",
        "pf status",
        "openbsd native operations",
    ]
    return any(marker in body for marker in exposed_markers) or len(body.strip()) > 512


def suspicious_body(body: str) -> bool:
    lowered = body.lower()
    markers = [
        "db_password",
        "app_key=",
        "wp-login",
        "phpinfo",
        "cmd=",
        "shell",
        "actuator",
        "server-status",
        "[core]",
    ]
    return any(marker in lowered for marker in markers)


def diagnostic_leak(body: str) -> bool:
    lowered = body.lower()
    markers = [
        "sql syntax",
        "sqlite",
        "postgres",
        "mariadb",
        "mysql",
        "thread '",
        "panicked at",
        "rust backtrace",
        "stack trace",
        "traceback",
        "exception",
        "root:x:0:0:",
    ]
    return any(marker in lowered for marker in markers)


def internal_content_leak(body: str) -> bool:
    lowered = body.lower()
    markers = [
        "osmap_serve(ok)",
        "rspamd",
        "redis_version",
        "mysql",
        "mariadb",
        "root:x:0:0:",
        "instance-id",
        "ami-id",
    ]
    return any(marker in lowered for marker in markers)


def tcp_state(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except socket.timeout:
        return "filtered_or_timeout"
    except OSError:
        return "closed_or_filtered"


def tls_handshake(host: str, port: int, timeout: float) -> dict[str, str]:
    try:
        context = osmap_tls_client_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return {
                    "status": "ok",
                    "version": tls_sock.version() or "",
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else "",
                    "peer": host,
                }
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return {"status": "error", "error": str(exc), "peer": host}


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")[:120] or "evidence"


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def env_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def build_config(args: argparse.Namespace) -> Config:
    merged = dict(load_env_file(PACK_ROOT / ".env"))
    merged.update({key: value for key, value in os.environ.items() if key.startswith("OSMAP_BORDER_")})
    base_url = args.base_url or merged.get("OSMAP_BORDER_BASE_URL", "https://mail.blackbagsecurity.com")
    parsed = urllib.parse.urlparse(base_url)
    host = args.host or merged.get("OSMAP_BORDER_HOST") or parsed.hostname or "mail.blackbagsecurity.com"
    output_dir = Path(args.output_dir or merged.get("OSMAP_BORDER_OUTPUT_DIR") or PACK_ROOT / "output").expanduser()
    allow_host = (
        args.include_host
        or env_truthy(merged.get("OSMAP_BORDER_ALLOW_HOST_ASSISTED_TESTS", "false"))
    ) and not args.no_host
    return Config(
        base_url=base_url.rstrip("/"),
        host=host,
        ssh_host=args.ssh_host or merged.get("OSMAP_BORDER_SSH_HOST", "mail.blackbagsecurity.com"),
        output_dir=output_dir,
        rate_delay=float(merged.get("OSMAP_BORDER_RATE_LIMIT_DELAY_SECONDS", "1")),
        timeout=float(merged.get("OSMAP_BORDER_REQUEST_TIMEOUT_SECONDS", "8")),
        allow_host_assisted=allow_host,
    )


def write_summary(runner: Runner, args: argparse.Namespace) -> None:
    counts = {status: 0 for status in [STATUS_PASS, STATUS_FAIL, STATUS_WARNING, STATUS_SKIP]}
    for result in runner.results:
        counts[result.status] = counts.get(result.status, 0) + 1
    summary = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "target": runner.config.base_url,
        "ssh_host": runner.config.ssh_host if runner.config.allow_host_assisted else None,
        "mapping_file": MAPPING_PATH.name,
        "commands": ["./run-border-pack.py " + " ".join(shlex.quote(arg) for arg in sys.argv[1:])],
        "counts": counts,
        "standards": runner.mapping["standards"],
        "results": [result.__dict__ for result in runner.results],
    }
    (runner.run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(runner, counts)


def write_report(runner: Runner, counts: dict[str, int]) -> None:
    lines = [
        "# OSMAP Border Security Test Report",
        "",
        f"- Target: `{runner.config.base_url}`",
        f"- SSH host: `{runner.config.ssh_host if runner.config.allow_host_assisted else 'not used'}`",
        f"- Generated: `{dt.datetime.now(dt.UTC).isoformat()}`",
        f"- Mapping: `{MAPPING_PATH.name}`",
        f"- Results: pass={counts.get(STATUS_PASS, 0)}, fail={counts.get(STATUS_FAIL, 0)}, warning={counts.get(STATUS_WARNING, 0)}, skip={counts.get(STATUS_SKIP, 0)}",
        "",
        "## Results",
        "",
        "| Status | Test ID | Test | Message | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in runner.results:
        evidence = "<br>".join(f"`{item}`" for item in result.evidence) or ""
        lines.append(
            f"| {escape_md(result.status)} | `{escape_md(result.test_id)}` | {escape_md(result.test_name)} | {escape_md(result.message)} | {evidence} |"
        )
    lines.extend([
        "",
        "## ATT&CK And OWASP Scope",
        "",
        "This suite adds safe border assurance for MITRE ATT&CK web and public-service techniques, especially T1071.001 Web Protocols, and maps each test to one or more OWASP Top 10 2021 categories. It does not emulate malware, perform denial-of-service testing, or attempt credential attacks.",
        "",
        "## Gaps",
        "",
        "| Gap ID | Area | Reason |",
        "| --- | --- | --- |",
    ])
    for gap in runner.mapping.get("gaps", []):
        lines.append(f"| `{escape_md(gap['gap_id'])}` | {escape_md(gap['area'])} | {escape_md(gap['reason'])} |")
    (runner.run_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def escape_md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Override OSMAP_BORDER_BASE_URL")
    parser.add_argument("--host", help="Override OSMAP_BORDER_HOST")
    parser.add_argument("--ssh-host", help="Override OSMAP_BORDER_SSH_HOST")
    parser.add_argument("--output-dir", help="Override OSMAP_BORDER_OUTPUT_DIR")
    parser.add_argument("--include-host", action="store_true", help="Run read-only host-assisted checks over ssh")
    parser.add_argument("--no-host", action="store_true", help="Disable host-assisted checks")
    parser.add_argument("--test-id", action="append", help="Run one test id; may be repeated")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    config = build_config(args)
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = config.output_dir / f"osmap-border-{timestamp}"
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
