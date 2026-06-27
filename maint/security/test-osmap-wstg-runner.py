#!/usr/bin/env python3
"""Behavioral regression tests for the OSMAP WSTG runner."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = REPO_ROOT / "maint" / "wstg-testing-pack"
RUNNER_PATH = PACK_ROOT / "run-wstg-pack.py"
SPEC = importlib.util.spec_from_file_location("osmap_wstg_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {RUNNER_PATH}")
WSTG = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WSTG
SPEC.loader.exec_module(WSTG)


class LoginHandler(BaseHTTPRequestHandler):
    """Minimal target used to prove that configured non-default ports work."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if self.path == "/nested/login":
            body = b'<input name="username"><input name="password"><input name="totp_code">'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def config(base_url: str, host: str, output_dir: Path) -> object:
    """Build the complete runner configuration needed by focused tests."""
    return WSTG.Config(
        base_url=base_url,
        host=host,
        ssh_host=host,
        test_email="",
        test_password="",
        totp_secret="",
        secondary_email="",
        output_dir=output_dir,
        rate_delay=0,
        allow_authenticated=False,
        prompt_auth=False,
        allow_host_assisted=False,
        throttle_attempts=1,
        timeout=0.2,
        ssh_timeout=1,
        release_mode=False,
        wstg_source_name="OWASP Web Security Testing Guide",
        wstg_source_url="https://owasp.org/www-project-web-security-testing-guide/v42/",
        wstg_source_version="v4.2",
        wstg_source_commit="",
        wstg_matrix_file="wstg-scenario-matrix.v42.json",
    )


class RunnerBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="osmap-wstg-runner-test.")
        self.root = Path(self.temp_dir.name)
        self.mapping = json.loads((PACK_ROOT / "wstg-asvs-mapping.json").read_text())

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_unreachable_target_cannot_produce_security_passes(self) -> None:
        runner = WSTG.Runner(
            config("http://127.0.0.1:9", "127.0.0.1", self.root),
            self.mapping,
            self.root / "unreachable",
        )
        selected = {
            "OSMAP-WSTG-CONF-004",
            "OSMAP-WSTG-INFO-001",
            "OSMAP-WSTG-INFO-002",
            "OSMAP-WSTG-INPV-001",
            "OSMAP-WSTG-INPV-002",
            "OSMAP-WSTG-CLNT-001",
        }
        results = runner.run(selected)
        self.assertEqual({result.test_id for result in results}, selected)
        self.assertTrue(all(result.status == WSTG.STATUS_FAIL for result in results))
        self.assertTrue(all(result.details.get("incomplete_evidence") for result in results))

    def test_non_default_port_and_mount_path_are_honored(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), LoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            runner = WSTG.Runner(
                config(f"http://127.0.0.1:{port}/nested", "127.0.0.1", self.root),
                self.mapping,
                self.root / "mounted",
            )
            evidence = runner.request("mounted_login", "GET", "/login")
            self.assertEqual(evidence.status, 200)
            self.assertIn('name="totp_code"', evidence.body_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_same_origin_includes_non_default_port(self) -> None:
        cfg = config("https://example.test:8443/app", "example.test", self.root)
        headers = WSTG.same_origin_headers(cfg)
        self.assertEqual(headers["Origin"], "https://example.test:8443")
        self.assertEqual(headers["Referer"], "https://example.test:8443/app/mailboxes")

    def test_raw_probe_is_scoped_to_mount_path_and_authority(self) -> None:
        cfg = config("https://example.test:8443/app", "example.test", self.root)
        runner = WSTG.Runner(cfg, self.mapping, self.root / "raw")
        scoped = runner.scope_raw_http_request(
            b"GET /login HTTP/1.1\r\nHost: stale.invalid\r\nConnection: close\r\n\r\n"
        )
        self.assertIn(b"GET /app/login HTTP/1.1", scoped)
        self.assertIn(b"Host: example.test:8443", scoped)

    def test_explicitly_allowed_closed_cleartext_port_is_not_incomplete(self) -> None:
        runner = WSTG.Runner(
            config("https://example.test", "example.test", self.root),
            self.mapping,
            self.root / "cleartext",
        )
        evidence = WSTG.HttpEvidence("cleartext", None, "", [], b"", error="connection refused")
        runner.record_response_completeness(evidence, allow_transport_failure=True)
        self.assertEqual(runner.test_incomplete_evidence, [])


if __name__ == "__main__":
    unittest.main()
