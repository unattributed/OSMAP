#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds python3
setup_run_dir "37-host-header-injection"

TARGET_HOST="${HOSTNAME}" TARGET_PORT=443 python3 - <<'PY'
import os, re, ssl, socket
from pathlib import Path
host = os.environ["TARGET_HOST"]
port = int(os.environ["TARGET_PORT"])
attacker = "attacker.invalid"
cases = {
    "baseline": f"GET /login HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "host_attacker": f"GET /login HTTP/1.1\r\nHost: {attacker}\r\nConnection: close\r\n\r\n",
    "xfh_attacker": f"GET /login HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-Host: {attacker}\r\nConnection: close\r\n\r\n",
    "host_and_xfh_attacker": f"GET /login HTTP/1.1\r\nHost: {attacker}\r\nX-Forwarded-Host: {attacker}\r\nConnection: close\r\n\r\n",
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
