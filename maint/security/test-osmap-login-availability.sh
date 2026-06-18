#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
script="${repo_root}/maint/openbsd/libexec/osmap-login-availability.ksh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-login-availability.XXXXXX")
trap 'rm -rf "${tmp_dir}"' EXIT HUP INT TERM

cat > "${tmp_dir}/nc" <<'EOF'
#!/bin/sh
request=$(cat)
if [ -f "${OSMAP_TEST_FAIL_FILE}" ]; then
  exit 1
fi
case "${request}" in
  "GET / HTTP/"*)
    printf 'HTTP/1.1 303 See Other\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n'
    ;;
  "GET /login HTTP/"*)
    printf 'HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n<title>OSMAP Login</title>'
    ;;
  *)
    exit 1
    ;;
esac
EOF

cat > "${tmp_dir}/rcctl" <<'EOF'
#!/bin/sh
[ "$1" = restart ] && [ "$2" = osmap_serve ]
rm -f "${OSMAP_TEST_FAIL_FILE}"
printf '%s\n' restart >> "${OSMAP_TEST_RESTART_LOG}"
EOF

cat > "${tmp_dir}/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF

chmod +x "${tmp_dir}/nc" "${tmp_dir}/rcctl" "${tmp_dir}/sleep"

export OSMAP_LOGIN_NC="${tmp_dir}/nc"
export OSMAP_LOGIN_RCCTL="${tmp_dir}/rcctl"
export OSMAP_LOGIN_SLEEP="${tmp_dir}/sleep"
export OSMAP_TEST_FAIL_FILE="${tmp_dir}/fail"
export OSMAP_TEST_RESTART_LOG="${tmp_dir}/restart.log"

sh "${script}" --check-only >/dev/null
[ ! -e "${OSMAP_TEST_RESTART_LOG}" ]

: > "${OSMAP_TEST_FAIL_FILE}"
if sh "${script}" --check-only >/dev/null 2>&1; then
  printf '%s\n' "expected check-only mode to fail while browser entry is unavailable" >&2
  exit 1
fi
[ ! -e "${OSMAP_TEST_RESTART_LOG}" ]

sh "${script}" --recover >/dev/null
grep -Fxq restart "${OSMAP_TEST_RESTART_LOG}"

printf '%s\n' "OSMAP login availability regression checks passed"
