#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds python3
setup_run_dir "36-request-smuggling-parser-check"

TARGET_HOST="${HOSTNAME}"
TARGET_PORT=443
TARGET_HOST="$TARGET_HOST" TARGET_PORT="$TARGET_PORT" python3 - <<'PY'
import os, re, ssl, socket
from pathlib import Path
host = os.environ["TARGET_HOST"]
port = int(os.environ["TARGET_PORT"])
cases = {
    "baseline_get": (
        f"GET /login HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ),
    "cl_te_probe": (
        f"POST /login HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n0\r\n\r\n"
    ),
    "te_cl_probe": (
        f"POST /login HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n0\r\n\r\n"
    ),
    "dup_cl_probe": (
        f"POST /login HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nContent-Length: 8\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\nx=1\n"
    ),
}
for name, req in cases.items():
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(req.encode())
            data = ssock.recv(4096).decode("utf-8", errors="replace")
    Path(f"{name}.txt").write_text(data)
    first = data.splitlines()[0] if data.splitlines() else "NO RESPONSE"
    title_match = re.search(r"<title>([^<]+)", data, re.I)
    cl_match = re.search(r"^Content-Length:\s*(\S+)", data, re.M | re.I)
    print(f"\n===== {name} =====")
    print(f"status={first}")
    print(f"title={title_match.group(1) if title_match else ''}")
    print(f"content_length={cl_match.group(1) if cl_match else ''}")
    print("response_prefix:")
    print("\n".join(data.splitlines()[:20]))
PY

printf '\nSaved in %s\n' "$RUN_DIR"
