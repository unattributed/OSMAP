#!/usr/bin/env python3
"""Behavioral regression tests for the OSMAP WSTG runner."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


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
        connect_timeout=0.2,
        response_timeout=0.4,
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

    def test_connection_and_response_deadlines_are_independent(self) -> None:
        cfg = replace(
            config("http://example.test", "example.test", self.root),
            connect_timeout=0.13,
            response_timeout=0.37,
        )
        runner = WSTG.Runner(cfg, self.mapping, self.root / "timeouts")
        connection = mock.Mock()
        connection.sock = mock.Mock()
        response = mock.Mock(status=200, reason="OK")
        response.getheaders.return_value = []
        response.read.side_effect = [b"ok", b""]
        connection.getresponse.return_value = response

        with mock.patch.object(
            WSTG.http.client, "HTTPConnection", return_value=connection
        ) as constructor:
            evidence = runner.request("timeout_split", "GET", "/login")

        constructor.assert_called_once_with("example.test", port=80, timeout=0.13)
        connection.connect.assert_called_once_with()
        connection.sock.settimeout.assert_called_once_with(0.37)
        self.assertEqual(evidence.status, 200)

    def test_authenticated_retry_preserves_both_attempt_labels(self) -> None:
        cfg = replace(
            config("https://example.test", "example.test", self.root),
            allow_authenticated=True,
            prompt_auth=True,
            release_mode=True,
            test_email="user@example.test",
        )
        runner = WSTG.Runner(cfg, self.mapping, self.root / "auth-retry")
        first = WSTG.HttpEvidence(
            "session_fixation",
            None,
            "",
            [],
            b"",
            error="read timed out",
        )
        retry = WSTG.HttpEvidence(
            "session_fixation_retry",
            303,
            "See Other",
            [("Set-Cookie", "osmap_session=fresh; Secure; HttpOnly")],
            b"",
        )

        with (
            mock.patch.object(runner, "auth_password", return_value="password"),
            mock.patch.object(runner, "auth_totp_code", return_value="123456"),
            mock.patch.object(runner, "form_post", side_effect=[first, retry]) as post,
            mock.patch.object(WSTG.time, "sleep"),
        ):
            evidence = runner.authenticated_login("session_fixation")

        self.assertEqual(evidence.status, 303)
        self.assertEqual(
            [call.args[0] for call in post.call_args_list],
            ["session_fixation", "session_fixation_retry"],
        )
        self.assertEqual(
            runner.authenticated_login_evidence_paths("session_fixation"),
            [
                "evidence/session_fixation.headers",
                "evidence/session_fixation_retry.headers",
            ],
        )

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
        hostile = runner.scope_raw_http_request(
            b"GET /login HTTP/1.1\r\nHost: attacker.invalid\r\n\r\n",
            rewrite_host=False,
        )
        self.assertIn(b"GET /app/login HTTP/1.1", hostile)
        self.assertIn(b"Host: attacker.invalid", hostile)

    def test_explicitly_allowed_closed_cleartext_port_is_not_incomplete(self) -> None:
        runner = WSTG.Runner(
            config("https://example.test", "example.test", self.root),
            self.mapping,
            self.root / "cleartext",
        )
        evidence = WSTG.HttpEvidence("cleartext", None, "", [], b"", error="connection refused")
        runner.record_response_completeness(evidence, allow_transport_failure=True)
        self.assertEqual(runner.test_incomplete_evidence, [])

    def test_release_rejects_missing_matrix(self) -> None:
        cfg = replace(
            config("https://example.test", "example.test", self.root),
            release_mode=True,
            wstg_matrix_file="/tmp/osmap-wstg-matrix-does-not-exist.json",
        )

        class ReleaseRunner:
            config = cfg

            @staticmethod
            def finalize_release_authentication_proof() -> list[str]:
                return []

        results = []
        for item in self.mapping["tests"]:
            status = (
                WSTG.STATUS_NA
                if WSTG.test_assurance_class(item) == "not_applicable"
                else WSTG.STATUS_PASS
            )
            results.append(WSTG.TestResult(item["test_id"], item["test_name"], status, "test"))
        errors = WSTG.release_errors(self.mapping, results, ReleaseRunner(), None)
        self.assertIn("active WSTG matrix does not exist", errors)
        self.assertIn("active WSTG matrix contains no scenarios", errors)

    def test_top10_reporting_separates_static_and_not_applicable_evidence(self) -> None:
        mapping = json.loads(json.dumps(self.mapping))
        tests = {item["test_id"]: item for item in mapping["tests"]}
        tests["OSMAP-WSTG-BUSL-005"]["test_type"] = ["static boundary review"]
        results = [
            WSTG.TestResult(
                "OSMAP-WSTG-BUSL-005",
                tests["OSMAP-WSTG-BUSL-005"]["test_name"],
                WSTG.STATUS_PASS,
                "static",
            ),
            WSTG.TestResult(
                "OSMAP-WSTG-INPV-007",
                tests["OSMAP-WSTG-INPV-007"]["test_name"],
                WSTG.STATUS_NA,
                "not applicable",
            ),
        ]
        coverage = WSTG.proven_top10_coverage(mapping, results)
        self.assertNotIn("OSMAP-WSTG-BUSL-005", coverage["A06:2025"]["tests"])
        self.assertIn("OSMAP-WSTG-BUSL-005", coverage["A06:2025"]["static_only_tests"])
        self.assertIn("OSMAP-WSTG-INPV-007", coverage["A05:2025"]["not_applicable_tests"])

    def test_browser_attack_surface_matches_runtime_router(self) -> None:
        runner = WSTG.Runner(
            config("https://example.test", "example.test", self.root),
            self.mapping,
            self.root / "attack-surface",
        )
        valid, findings = runner.write_attack_surface_inventory_evidence()
        self.assertTrue(valid, findings)

    def test_webmail_static_evidence_scans_draft_persistence(self) -> None:
        runner = WSTG.Runner(
            config("https://example.test", "example.test", self.root),
            self.mapping,
            self.root / "webmail-static",
        )
        self.assertTrue(runner.write_webmail_input_validation_static_evidence())

    def test_nonzero_ssh_exit_is_explicitly_incomplete(self) -> None:
        runner = WSTG.Runner(
            config("https://example.test", "example.test", self.root),
            self.mapping,
            self.root / "ssh-failure",
        )
        completed = mock.Mock(returncode=23, stdout="")
        with mock.patch.object(WSTG.subprocess, "run", return_value=completed):
            output = runner.run_ssh("ssh_failure.txt", "false")
        self.assertEqual(output, "ERROR: ssh command exited with status 23\n")
        evidence = runner.evidence_dir / "ssh_failure.txt"
        self.assertEqual(evidence.read_text(), output)


if __name__ == "__main__":
    unittest.main()
