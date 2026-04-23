#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds python3
setup_run_dir "37-host-header-injection"

TARGET_HOST="${HOSTNAME}" TARGET_PORT="$TARGET_PORT" TARGET_TLS="$TARGET_TLS" LOGIN_PATH="$LOGIN_PATH" python3 - <<'PY'
import os, re, ssl, socket
from pathlib import Path
host = os.environ["TARGET_HOST"]
port = int(os.environ["TARGET_PORT"])
use_tls = os.environ.get("TARGET_TLS") == "1"
login_path = os.environ.get("LOGIN_PATH", "/login")
attacker = "attacker.invalid"
cases = {
    "baseline": f"GET {login_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "host_attacker": f"GET {login_path} HTTP/1.1\r\nHost: {attacker}\r\nConnection: close\r\n\r\n",
    "xfh_attacker": f"GET {login_path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-Host: {attacker}\r\nConnection: close\r\n\r\n",
    "host_and_xfh_attacker": f"GET {login_path} HTTP/1.1\r\nHost: {attacker}\r\nX-Forwarded-Host: {attacker}\r\nConnection: close\r\n\r\n",
}
def exchange(req):
    with socket.create_connection((host, port), timeout=8) as sock:
        if use_tls:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req.encode())
                return ssock.recv(4096).decode("utf-8", errors="replace")
        sock.sendall(req.encode())
        return sock.recv(4096).decode("utf-8", errors="replace")

for name, req in cases.items():
    data = exchange(req)
    Path(f"{name}.txt").write_text(data)
    first = data.splitlines()[0] if data.splitlines() else "NO RESPONSE"
    title_match = re.search(r"<title>([^<]+)", data, re.I)
    location_match = re.search(r"^Location:\s*(.+)$", data, re.M | re.I)
    print(f"\n===== {name} =====")
    print(f"status={first}")
    print(f"title={title_match.group(1) if title_match else ''}")
    print(f"location={location_match.group(1) if location_match else ''}")
    print(f"attacker_reflected={'attacker.invalid' in data}")
    print("response_prefix:")
    print("\n".join(data.splitlines()[:20]))
PY

printf '\nSaved in %s\n' "$RUN_DIR"
