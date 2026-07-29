#!/usr/bin/env python3
"""Regression tests for the OSMAP HTTP differential harness."""

from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import sys
import tempfile

repo = Path(sys.argv[1]).resolve()
harness_path = repo / "maint/security/osmap-v15-http-differential.py"
corpus_path = repo / "maint/security/v15-http-differential-corpus.json"

spec = importlib.util.spec_from_file_location("osmap_http_diff", harness_path)
if spec is None or spec.loader is None:
    raise SystemExit("FAIL: could not load differential harness")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

corpus = module.load_corpus(corpus_path)
cases = corpus["cases"]

if len(cases) != 37:
    raise SystemExit("FAIL: corpus does not contain 37 cases")
if len({case["id"] for case in cases}) != 37:
    raise SystemExit("FAIL: corpus IDs are not unique")


remote_command = f"python3 -c {module.shlex.quote('print((1 + 2))')}"
if module.shlex.split(remote_command) != ["python3", "-c", "print((1 + 2))"]:
    raise SystemExit("FAIL: remote Python command quoting differs")
if len(module.shlex.split(remote_command)) != 3:
    raise SystemExit("FAIL: remote Python source was split by the shell")

required_ids = {
    "valid_get",
    "leading_request_line_whitespace",
    "content_length_plus_transfer_encoding",
    "pipelined_second_request",
    "oversized_header_block",
}
actual_ids = {case["id"] for case in cases}
if not required_ids.issubset(actual_ids):
    raise SystemExit("FAIL: corpus lacks required case classes")

rendered = {
    case["id"]: module.render_request(
        case,
        "mail.blackbagsecurity.com",
        f"OSMAPS03-TEST-{case['id']}",
    )
    for case in cases
}
if any(not value for value in rendered.values()):
    raise SystemExit("FAIL: one or more rendered requests are empty")
if any(b"{token}" in value or b"{authority}" in value for value in rendered.values()):
    raise SystemExit("FAIL: one or more request placeholders remain")

if b"\r\n\r\n" not in rendered["valid_get"]:
    raise SystemExit("FAIL: canonical control lost CRLF framing")
if b"\n\n" not in rendered["bare_lf_header_lines"]:
    raise SystemExit("FAIL: bare-LF case was normalized")
if b"GET\t/login" not in rendered["tab_request_line_separator"]:
    raise SystemExit("FAIL: HTAB request-line case was normalized")
if len(rendered["oversized_request_line"]) <= 2048:
    raise SystemExit("FAIL: oversized request-line generator is too small")
if len(rendered["oversized_header_block"]) <= 16 * 1024:
    raise SystemExit("FAIL: oversized header block is too small")

accepted = {"accepted": True}
rejected = {"accepted": False}
expected = [
    ("ACCEPT", accepted, "PASS"),
    ("ACCEPT", rejected, "FAIL"),
    ("REJECT_CLOSE", rejected, "PASS"),
    ("REJECT_CLOSE", accepted, "FAIL"),
    ("MEASURE", accepted, "MEASURED"),
]
for policy, oracle, state in expected:
    actual, _ = module.origin_policy_result(policy, oracle)
    if actual != state:
        raise SystemExit(
            f"FAIL: origin policy classification differs: {policy}"
        )

response_200 = module.parse_raw_response(
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    connection_closed=True,
    timed_out=False,
)
response_400 = module.parse_raw_response(
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
    connection_closed=True,
    timed_out=False,
)
if response_200.status != 200 or response_200.response_count != 1:
    raise SystemExit("FAIL: 200 response parser differs")
if response_400.status != 400:
    raise SystemExit("FAIL: 400 response parser differs")

if module.edge_policy_result("ACCEPT", response_200)[0] != "PASS":
    raise SystemExit("FAIL: edge ACCEPT classification differs")
if module.edge_policy_result("REJECT_OR_CLOSE", response_400)[0] != "PASS":
    raise SystemExit("FAIL: edge rejection classification differs")
if module.edge_policy_result("REJECT_OR_CLOSE", response_200)[0] != "FAIL":
    raise SystemExit("FAIL: successful hostile edge response was not rejected")

closed = module.parse_raw_response(
    b"",
    connection_closed=True,
    timed_out=False,
)
if module.edge_policy_result("REJECT_OR_CLOSE", closed)[0] != "PASS":
    raise SystemExit("FAIL: connection-close rejection differs")

with tempfile.TemporaryDirectory(prefix="osmap-http-diff-test.") as temp:
    output = Path(temp)
    result = {
        "schema": module.RESULT_SCHEMA,
        "mode": "offline",
        "enforcement": "inventory",
        "run_id": "OSMAPS03-TEST",
        "authority": "mail.blackbagsecurity.com",
        "case_count": 1,
        "required_policy_failures": 0,
        "measured_only_cases": 0,
        "host_log_capture_sha256": None,
        "cases": [{
            "id": "valid_get",
            "class": "control",
            "required_origin_policy": "ACCEPT",
            "oracle": accepted,
            "origin_policy_result": "PASS",
        }],
    }
    module.write_reports(output, result)
    parsed = json.loads(
        (output / "http-differential-results.json").read_text(
            encoding="utf-8"
        )
    )
    if parsed["schema"] != module.RESULT_SCHEMA:
        raise SystemExit("FAIL: JSON report schema differs")
    if not (output / "http-differential-results.md").is_file():
        raise SystemExit("FAIL: Markdown report was not written")

print("PASS: HTTP differential harness regression tests passed")
