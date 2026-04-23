#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "65-websockets-check"

perform_login cookies.txt login.headers login.body.html
printf '===== HTML websocket token scan =====\n'
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n--- %s ---\n' "$label"
  grep -Eoin 'ws://|wss://|WebSocket|SockJS|socket\.io|EventSource|SSE|/ws|/socket|/websocket|/notifications|/live' "${label}.html" | sed -n '1,60p'
done <<EOF
login ${LOGIN_PATH}
mailboxes ${MAILBOXES_PATH}
compose ${COMPOSE_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\n===== direct websocket handshake probes =====\n'
python3 - <<'PY'
import base64, os, ssl, socket
host = os.environ["HOSTNAME"]
port = int(os.environ["TARGET_PORT"])
scheme = os.environ.get("SCHEME", "https")
use_tls = os.environ.get("TARGET_TLS") == "1"
paths = os.environ["WEBSOCKET_PATHS"].split()
cookie = ""
with open("cookies.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if not line.startswith("#") and "\tosmap_session\t" in line:
            cookie = line.strip().split("\t")[-1]
            break
for path in paths:
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {scheme}://{host}\r\n"
        + (f"Cookie: osmap_session={cookie}\r\n" if cookie else "")
        + "\r\n"
    )
    with socket.create_connection((host, port), timeout=8) as sock:
        if use_tls:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req.encode())
                data = ssock.recv(4096).decode("utf-8", errors="replace")
        else:
            sock.sendall(req.encode())
            data = sock.recv(4096).decode("utf-8", errors="replace")
    first = data.splitlines()[0] if data.splitlines() else "NO RESPONSE"
    print(f"\n===== {path} =====")
    print(first)
    print("\n".join(data.splitlines()[:20]))
PY

printf '\nSaved in %s\n' "$RUN_DIR"
