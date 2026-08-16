#!/bin/sh

set -eu

if ! command -v nginx >/dev/null 2>&1; then
  printf '%s\n' "note: nginx is unavailable; skipping V15 edge runtime check"
  exit 0
fi

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v15-nginx.XXXXXXXX")
origin_pid=
nginx_pid=
cleanup() {
  if [ -n "${nginx_pid}" ]; then
    kill -TERM "${nginx_pid}" 2>/dev/null || true
    wait "${nginx_pid}" 2>/dev/null || true
  fi
  if [ -n "${origin_pid}" ]; then
    kill -TERM "${origin_pid}" 2>/dev/null || true
    wait "${origin_pid}" 2>/dev/null || true
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT HUP INT TERM

ports=$(python3 - <<'PY'
import socket

sockets = []
ports = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
for sock in sockets:
    sock.close()
PY
)
set -- ${ports}
origin_port=$1
edge_port=$2

cat >"${temp_dir}/origin.py" <<'PY'
import pathlib
import socket
import sys

port = int(sys.argv[1])
record = pathlib.Path(sys.argv[2])
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen()
    while True:
        connection, _ = listener.accept()
        with connection:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                request.extend(chunk)
            first_line = bytes(request).split(b"\r\n", 1)[0]
            with record.open("ab") as output:
                output.write(first_line + b"\n")
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
PY

: >"${temp_dir}/origin-requests.txt"
mkdir -p \
  "${temp_dir}/logs" \
  "${temp_dir}/client_temp" \
  "${temp_dir}/proxy_temp" \
  "${temp_dir}/fastcgi_temp" \
  "${temp_dir}/uwsgi_temp" \
  "${temp_dir}/scgi_temp"
python3 "${temp_dir}/origin.py" \
  "${origin_port}" "${temp_dir}/origin-requests.txt" &
origin_pid=$!

cat >"${temp_dir}/nginx.conf" <<EOF
worker_processes 1;
error_log ${temp_dir}/error.log notice;
pid ${temp_dir}/nginx.pid;
events { worker_connections 32; }
http {
    access_log off;
    client_body_temp_path ${temp_dir}/client_temp;
    proxy_temp_path ${temp_dir}/proxy_temp;
    fastcgi_temp_path ${temp_dir}/fastcgi_temp;
    uwsgi_temp_path ${temp_dir}/uwsgi_temp;
    scgi_temp_path ${temp_dir}/scgi_temp;
    server {
        listen 127.0.0.1:${edge_port};
        location / {
            keepalive_timeout 0;
            proxy_pass http://127.0.0.1:${origin_port};
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_buffering off;
        }
    }
}
EOF

nginx -p "${temp_dir}/" -c "${temp_dir}/nginx.conf"
nginx_pid=$(cat "${temp_dir}/nginx.pid")

python3 - "${edge_port}" "${temp_dir}/responses.txt" <<'PY'
import pathlib
import socket
import sys
import time

port = int(sys.argv[1])
output = pathlib.Path(sys.argv[2])

for _ in range(100):
    try:
        probe = socket.create_connection(("127.0.0.1", port), timeout=0.1)
        probe.close()
        break
    except OSError:
        time.sleep(0.02)
else:
    raise SystemExit("nginx test listener did not start")

request = (
    b"GET /first HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: keep-alive\r\n\r\n"
    b"GET /forbidden-second HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
    client.settimeout(2)
    client.sendall(request)
    response = bytearray()
    while True:
        data = client.recv(4096)
        if not data:
            break
        response.extend(data)
output.write_bytes(response)

with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
    client.sendall(
        b"GET /separate-control HTTP/1.1\r\nHost: localhost\r\n"
        b"Connection: close\r\n\r\n"
    )
    while client.recv(4096):
        pass
PY

nginx -p "${temp_dir}/" -c "${temp_dir}/nginx.conf" -s quit
wait "${nginx_pid}" 2>/dev/null || true
nginx_pid=
kill -TERM "${origin_pid}"
wait "${origin_pid}" 2>/dev/null || true
origin_pid=

request_count=$(wc -l <"${temp_dir}/origin-requests.txt" | tr -d ' ')
[ "${request_count}" -eq 2 ] || {
  printf 'expected two origin requests across two client connections, got %s\n' \
    "${request_count}" >&2
  exit 1
}
grep -Fxq "GET /first HTTP/1.1" "${temp_dir}/origin-requests.txt"
grep -Fxq "GET /separate-control HTTP/1.1" "${temp_dir}/origin-requests.txt"
if grep -Fq "/forbidden-second" "${temp_dir}/origin-requests.txt"; then
  printf '%s\n' "pipelined second request reached the origin" >&2
  exit 1
fi

response_count=$(grep -ao "HTTP/1.1 200" "${temp_dir}/responses.txt" | wc -l | tr -d ' ')
[ "${response_count}" -eq 1 ] || {
  printf 'expected one response for pipelined submission, got %s\n' \
    "${response_count}" >&2
  exit 1
}

printf '%s\n' "PASS: nginx closes OSMAP client connections after one request"
