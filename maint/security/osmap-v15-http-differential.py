#!/usr/bin/env python3
"""Byte-preserving OSMAP HTTP edge/origin differential harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import shlex
import socket
import ssl
import subprocess
import sys
from typing import Any

CORPUS_SCHEMA = "osmap-v15-http-differential-corpus-v1"
RESULT_SCHEMA = "osmap-v15-http-differential-result-v1"
ORIGIN_POLICIES = {"ACCEPT", "REJECT_CLOSE", "MEASURE"}
EDGE_POLICIES = {"ACCEPT", "REJECT_OR_CLOSE", "MEASURE"}
REJECT_STATUS = {400, 408, 411, 413, 414, 421, 431, 501, 505}


@dataclass
class RawHttpResponse:
    status: int | None
    reason: str
    headers: list[tuple[str, str]]
    body_b64: str
    raw_sha256: str
    raw_length: int
    response_count: int
    connection_closed: bool
    timed_out: bool
    error: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def load_corpus(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != CORPUS_SCHEMA:
        fail(f"unsupported corpus schema: {value.get('schema')!r}")
    cases = value.get("cases")
    if not isinstance(cases, list):
        fail("corpus cases must be an array")
    if value.get("case_count") != len(cases):
        fail("corpus case_count differs from the cases array")
    if len(cases) != 37:
        fail(f"expected 37 corpus cases, found {len(cases)}")

    identifiers: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            fail(f"cases[{index}] must be an object")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(
            r"[a-z0-9_]+", case_id
        ):
            fail(f"cases[{index}].id is invalid")
        if case_id in identifiers:
            fail(f"duplicate corpus case ID: {case_id}")
        identifiers.add(case_id)

        origin_policy = case.get("required_origin_policy")
        edge_policy = case.get("required_edge_policy")
        if origin_policy not in ORIGIN_POLICIES:
            fail(f"{case_id} has unsupported origin policy")
        if edge_policy not in EDGE_POLICIES:
            fail(f"{case_id} has unsupported edge policy")

        has_template = isinstance(case.get("request_template"), str)
        has_generator = isinstance(case.get("generator"), dict)
        if has_template == has_generator:
            fail(
                f"{case_id} must define exactly one request_template "
                "or generator"
            )

    return value


def generate_request(
    generator: dict[str, Any],
    authority: str,
    token: str,
) -> bytes:
    kind = generator.get("kind")
    if kind == "oversized_request_line":
        target_bytes = int(generator.get("target_bytes", 0))
        if target_bytes <= 2048:
            fail("oversized_request_line must exceed 2048 bytes")
        prefix = f"/oversized?osmap_s03={token}&padding="
        padding = "a" * max(1, target_bytes - len(prefix))
        target = (prefix + padding)[:target_bytes]
        return (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

    if kind == "oversized_header_field":
        value_bytes = int(generator.get("value_bytes", 0))
        if value_bytes <= 8192:
            fail("oversized_header_field must exceed 8192 bytes")
        return (
            f"GET /login?osmap_s03={token} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"X-Oversized: {'a' * value_bytes}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

    if kind == "oversized_header_block":
        block_bytes = int(generator.get("block_bytes", 0))
        if block_bytes <= 16 * 1024:
            fail("oversized_header_block must exceed 16 KiB")
        lines = [
            f"GET /login?osmap_s03={token} HTTP/1.1",
            f"Host: {authority}",
        ]
        index = 0
        while len("\r\n".join(lines).encode("ascii")) < block_bytes:
            lines.append(f"X-Pad-{index}: {'a' * 180}")
            index += 1
        lines.extend(["Connection: close", "", ""])
        return "\r\n".join(lines).encode("ascii")

    fail(f"unsupported request generator: {kind!r}")


def render_request(
    case: dict[str, Any],
    authority: str,
    token: str,
) -> bytes:
    template = case.get("request_template")
    if isinstance(template, str):
        rendered = template.replace("{authority}", authority).replace(
            "{token}", token
        )
        return rendered.encode("utf-8")
    generator = case.get("generator")
    if isinstance(generator, dict):
        return generate_request(generator, authority, token)
    fail(f"{case.get('id')} has no request source")


def parse_raw_response(
    response: bytes,
    *,
    connection_closed: bool,
    timed_out: bool,
    error: str = "",
) -> RawHttpResponse:
    response_count = len(
        re.findall(rb"(?m)^HTTP/\S+\s+\d{3}\b", response)
    )
    status = None
    reason = ""
    headers: list[tuple[str, str]] = []
    body = b""

    if response:
        header_bytes, separator, body = response.partition(b"\r\n\r\n")
        if not separator:
            header_bytes, separator, body = response.partition(b"\n\n")
        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        lines = header_text.replace("\r\n", "\n").split("\n")
        if lines:
            match = re.match(
                r"^HTTP/\S+\s+(\d{3})(?:\s+(.*))?$",
                lines[0],
            )
            if match:
                status = int(match.group(1))
                reason = match.group(2) or ""
                for line in lines[1:]:
                    if not line or ":" not in line:
                        continue
                    name, value = line.split(":", 1)
                    headers.append((name.strip(), value.strip()))
            elif not error:
                error = "response did not start with an HTTP status line"

    return RawHttpResponse(
        status=status,
        reason=reason,
        headers=headers,
        body_b64=base64.b64encode(body[:4096]).decode("ascii"),
        raw_sha256=hashlib.sha256(response).hexdigest(),
        raw_length=len(response),
        response_count=response_count,
        connection_closed=connection_closed,
        timed_out=timed_out,
        error=error,
    )


def send_tcp_request(
    host: str,
    port: int,
    request: bytes,
    *,
    timeout: float,
) -> RawHttpResponse:
    response = bytearray()
    connection_closed = False
    timed_out = False
    error = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            while len(response) < 1024 * 1024:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    timed_out = True
                    break
                if not chunk:
                    connection_closed = True
                    break
                response.extend(chunk)
    except OSError as exc:
        error = str(exc)

    return parse_raw_response(
        bytes(response),
        connection_closed=connection_closed,
        timed_out=timed_out,
        error=error,
    )


def send_tls_request(
    host: str,
    port: int,
    request: bytes,
    *,
    timeout: float,
) -> RawHttpResponse:
    response = bytearray()
    connection_closed = False
    timed_out = False
    error = ""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.settimeout(timeout)
                tls.sendall(request)
                while len(response) < 1024 * 1024:
                    try:
                        chunk = tls.recv(65536)
                    except socket.timeout:
                        timed_out = True
                        break
                    except ssl.SSLError as exc:
                        error = str(exc)
                        break
                    if not chunk:
                        connection_closed = True
                        break
                    response.extend(chunk)
    except (OSError, ssl.SSLError) as exc:
        error = str(exc)

    return parse_raw_response(
        bytes(response),
        connection_closed=connection_closed,
        timed_out=timed_out,
        error=error,
    )


REMOTE_DIRECT_RUNNER = r"""
import base64
import json
import socket
import sys

request_data = json.load(sys.stdin)
host = request_data["host"]
port = int(request_data["port"])
timeout = float(request_data["timeout"])
results = []

for item in request_data["requests"]:
    raw = base64.b64decode(item["request_b64"])
    response = bytearray()
    closed = False
    timed_out = False
    error = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(raw)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            while len(response) < 1024 * 1024:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    timed_out = True
                    break
                if not chunk:
                    closed = True
                    break
                response.extend(chunk)
    except OSError as exc:
        error = str(exc)
    results.append({
        "id": item["id"],
        "response_b64": base64.b64encode(bytes(response)).decode("ascii"),
        "connection_closed": closed,
        "timed_out": timed_out,
        "error": error,
    })

json.dump(results, sys.stdout, sort_keys=True)
"""


def direct_origin_batch(
    ssh_host: str,
    host: str,
    port: int,
    timeout: float,
    requests: list[tuple[str, bytes]],
) -> dict[str, RawHttpResponse]:
    payload = {
        "host": host,
        "port": port,
        "timeout": timeout,
        "requests": [
            {
                "id": case_id,
                "request_b64": base64.b64encode(request).decode("ascii"),
            }
            for case_id, request in requests
        ],
    }
    completed = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            ssh_host,
            "python3",
            "-c",
            REMOTE_DIRECT_RUNNER,
        ],
        input=json.dumps(payload),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            "direct-origin SSH runner failed: "
            f"status={completed.returncode} stderr={completed.stderr.strip()}"
        )
    decoded = json.loads(completed.stdout)
    results: dict[str, RawHttpResponse] = {}
    for item in decoded:
        raw = base64.b64decode(item["response_b64"])
        results[item["id"]] = parse_raw_response(
            raw,
            connection_closed=bool(item["connection_closed"]),
            timed_out=bool(item["timed_out"]),
            error=str(item["error"]),
        )
    return results


def run_oracle(
    oracle: Path,
    authority: str,
    request: bytes,
) -> dict[str, Any]:
    completed = subprocess.run(
        [str(oracle), authority],
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            "parser oracle failed: "
            f"status={completed.returncode} "
            f"stderr={completed.stderr.decode(errors='replace').strip()}"
        )
    try:
        return json.loads(completed.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"parser oracle returned invalid JSON: {exc}")


def origin_policy_result(
    required_policy: str,
    oracle_result: dict[str, Any],
) -> tuple[str, str]:
    accepted = oracle_result.get("accepted")
    if not isinstance(accepted, bool):
        return "FAIL", "oracle result lacks boolean accepted"

    if required_policy == "MEASURE":
        return "MEASURED", "case is observation-only"
    if required_policy == "ACCEPT":
        if accepted:
            return "PASS", "origin parser accepted required control"
        return "FAIL", "origin parser rejected a required control"
    if required_policy == "REJECT_CLOSE":
        if not accepted:
            return "PASS", "origin parser rejected required hostile shape"
        return "FAIL", "origin parser accepted a shape required to reject"
    return "FAIL", f"unsupported origin policy {required_policy!r}"


def edge_policy_result(
    required_policy: str,
    response: RawHttpResponse,
) -> tuple[str, str]:
    if required_policy == "MEASURE":
        return "MEASURED", "edge behaviour is observation-only"
    if required_policy == "ACCEPT":
        if response.status is not None and response.status < 400:
            return "PASS", "edge accepted required control"
        return "FAIL", "edge did not accept required control"
    if required_policy == "REJECT_OR_CLOSE":
        if response.status is None:
            if response.connection_closed or response.timed_out or response.error:
                return "PASS", "edge rejected or closed without a successful response"
            return "FAIL", "edge returned no classifiable outcome"
        if response.status in REJECT_STATUS or response.status >= 400:
            return "PASS", "edge returned a rejecting status"
        return "FAIL", "edge returned a successful status for a hostile shape"
    return "FAIL", f"unsupported edge policy {required_policy!r}"


def capture_host_logs(ssh_host: str, run_prefix: str) -> str:
    quoted = shlex.quote(run_prefix)
    command = (
        "set -eu; "
        f"prefix={quoted}; "
        "printf '%s\n' '--- nginx access log ---'; "
        "doas grep -F \"$prefix\" "
        "/var/log/nginx/osmap.public.access.log 2>/dev/null | tail -200 || true; "
        "printf '%s\n' '--- nginx error log ---'; "
        "doas grep -F \"$prefix\" "
        "/var/log/nginx/osmap.public.error.log 2>/dev/null | tail -200 || true; "
        "printf '%s\n' '--- osmap serve log ---'; "
        "doas grep -F \"$prefix\" "
        "/var/log/osmap/serve.log 2>/dev/null | tail -200 || true"
    )
    completed = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            ssh_host,
            command,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            "host log capture failed: "
            f"status={completed.returncode} stderr={completed.stderr.strip()}"
        )
    return completed.stdout


def write_reports(
    output_dir: Path,
    result: dict[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "http-differential-results.json"
    json_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    rows = [
        "# OSMAP V15 HTTP Differential Results",
        "",
        f"- Mode: `{result['mode']}`",
        f"- Run ID: `{result['run_id']}`",
        f"- Cases: {result['case_count']}",
        f"- Required-policy failures: {result['required_policy_failures']}",
        f"- Measured-only cases: {result['measured_only_cases']}",
        "",
        "| Case | Class | Origin policy | Oracle | Origin result | Edge result |",
        "|---|---|---|---|---|---|",
    ]
    for item in result["cases"]:
        edge_result = item.get("edge_policy_result", "not-run")
        rows.append(
            f"| `{item['id']}` | `{item['class']}` | "
            f"`{item['required_origin_policy']}` | "
            f"`{'accept' if item['oracle']['accepted'] else 'reject'}` | "
            f"`{item['origin_policy_result']}` | `{edge_result}` |"
        )
    rows.extend([
        "",
        "A non-zero required-policy failure count is a remediation finding, "
        "not a harness execution failure when enforcement is `inventory`.",
        "",
    ])
    (output_dir / "http-differential-results.md").write_text(
        "\n".join(rows),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--authority", default="mail.blackbagsecurity.com")
    parser.add_argument(
        "--mode",
        choices=("offline", "live"),
        default="offline",
    )
    parser.add_argument(
        "--enforcement",
        choices=("inventory", "required-policy"),
        default="inventory",
    )
    parser.add_argument("--edge-host", default="mail.blackbagsecurity.com")
    parser.add_argument("--edge-port", type=int, default=443)
    parser.add_argument("--ssh-host", default="mail")
    parser.add_argument("--direct-host", default="127.0.0.1")
    parser.add_argument("--direct-port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=4.0)
    arguments = parser.parse_args()

    corpus = load_corpus(arguments.corpus)
    run_id = (
        "OSMAPS03-"
        + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    rendered: list[tuple[dict[str, Any], str, bytes]] = []
    for case in corpus["cases"]:
        token = f"{run_id}-{case['id']}"
        raw = render_request(case, arguments.authority, token)
        rendered.append((case, token, raw))

    direct_results: dict[str, RawHttpResponse] = {}
    if arguments.mode == "live":
        direct_results = direct_origin_batch(
            arguments.ssh_host,
            arguments.direct_host,
            arguments.direct_port,
            arguments.timeout,
            [(case["id"], raw) for case, _, raw in rendered],
        )

    results = []
    required_failures = 0
    measured = 0

    for case, token, raw in rendered:
        oracle_result = run_oracle(
            arguments.oracle,
            arguments.authority,
            raw,
        )
        origin_state, origin_message = origin_policy_result(
            case["required_origin_policy"],
            oracle_result,
        )
        if origin_state == "FAIL":
            required_failures += 1
        elif origin_state == "MEASURED":
            measured += 1

        item: dict[str, Any] = {
            "id": case["id"],
            "class": case["class"],
            "rationale": case["rationale"],
            "token": token,
            "request_sha256": hashlib.sha256(raw).hexdigest(),
            "request_length": len(raw),
            "request_b64": base64.b64encode(raw).decode("ascii"),
            "required_origin_policy": case["required_origin_policy"],
            "required_edge_policy": case["required_edge_policy"],
            "oracle": oracle_result,
            "origin_policy_result": origin_state,
            "origin_policy_message": origin_message,
        }

        if arguments.mode == "live":
            edge = send_tls_request(
                arguments.edge_host,
                arguments.edge_port,
                raw,
                timeout=arguments.timeout,
            )
            direct = direct_results[case["id"]]
            edge_state, edge_message = edge_policy_result(
                case["required_edge_policy"],
                edge,
            )
            if edge_state == "FAIL":
                required_failures += 1
            elif edge_state == "MEASURED":
                measured += 1
            item.update({
                "edge": edge.to_dict(),
                "direct_origin": direct.to_dict(),
                "edge_policy_result": edge_state,
                "edge_policy_message": edge_message,
            })

        results.append(item)

    host_logs = ""
    if arguments.mode == "live":
        host_logs = capture_host_logs(arguments.ssh_host, run_id)
        arguments.output_dir.mkdir(parents=True, exist_ok=True)
        (arguments.output_dir / "http-differential-host-logs.txt").write_text(
            host_logs,
            encoding="utf-8",
        )

    report = {
        "schema": RESULT_SCHEMA,
        "mode": arguments.mode,
        "enforcement": arguments.enforcement,
        "run_id": run_id,
        "authority": arguments.authority,
        "case_count": len(results),
        "required_policy_failures": required_failures,
        "measured_only_cases": measured,
        "host_log_capture_sha256": (
            hashlib.sha256(host_logs.encode("utf-8")).hexdigest()
            if host_logs
            else None
        ),
        "cases": results,
    }
    write_reports(arguments.output_dir, report)

    print(f"mode={arguments.mode}")
    print(f"run_id={run_id}")
    print(f"case_count={len(results)}")
    print(f"required_policy_failures={required_failures}")
    print(f"measured_only_cases={measured}")
    print("PASS: HTTP differential harness completed")

    if arguments.enforcement == "required-policy" and required_failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
