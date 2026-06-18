#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="$repo_root/maint/live/osmap-live-validate-v6-production-readiness.ksh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-production.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

bin_dir="$tmp_dir/bin"
live_dir="$tmp_dir/live"
mkdir -p "$bin_dir" "$live_dir/bin" "$live_dir/etc" "$live_dir/log" "$live_dir/run"

printf 'binary\n' > "$live_dir/bin/osmap"
cat > "$live_dir/etc/osmap-serve.env" <<'EOF'
OSMAP_ALLOWED_HOSTS=mail.blackbagsecurity.com
EOF
printf 'log\n' > "$live_dir/log/serve.log"
printf 'log\n' > "$live_dir/log/helper.log"
printf 'socket\n' > "$live_dir/run/mailbox-helper.sock"
printf 'backup\n' > "$live_dir/bin/osmap.pre-fixture"
printf 'backup\n' > "$live_dir/etc/osmap-serve.env.pre-fixture"

cat > "$bin_dir/doas" <<'EOF'
#!/bin/sh
exec "$@"
EOF
cat > "$bin_dir/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' 'mail.blackbagsecurity.com'
EOF
cat > "$bin_dir/git" <<'EOF'
#!/bin/sh
printf '%s\n' 'cafebabecafebabecafebabecafebabecafebabe'
EOF
cat > "$bin_dir/sha256" <<'EOF'
#!/bin/sh
printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
EOF
cat > "$bin_dir/rcctl" <<'EOF'
#!/bin/sh
case "$*" in
  'check osmap_serve'|'check osmap_mailbox_helper') exit "${OSMAP_TEST_SERVICE_RC:-0}" ;;
esac
exit 1
EOF
cat > "$bin_dir/stat" <<'EOF'
#!/bin/sh
path=
for arg in "$@"; do path=$arg; done
case "$path" in
  */osmap-serve.env) printf '%s\n' 'root:osmaprt:640' ;;
  */mailbox-helper.sock) printf '%s\n' 'vmail:osmaprt:660' ;;
  *) printf '%s\n' '_osmap:_osmap:600' ;;
esac
EOF
cat > "$bin_dir/curl" <<'EOF'
#!/bin/sh
case "$*" in
  *'Host: attacker.invalid'*) printf '%s' "${OSMAP_TEST_INVALID_CODE:-421}" ;;
  *) printf '%s' "${OSMAP_TEST_VALID_CODE:-200}" ;;
esac
EOF
cat > "$bin_dir/netstat" <<'EOF'
#!/bin/sh
cat <<OUT
tcp 0 0 ${OSMAP_TEST_BACKEND_BINDING:-127.0.0.1.8080} *.* LISTEN
tcp 0 0 192.168.1.44.443 *.* LISTEN
OUT
EOF
chmod +x "$bin_dir"/*

run_validator() {
	report=$1
	shift
	env \
		PATH="$bin_dir:$PATH" \
		OSMAP_V6_OSMAP_BIN_PATH="$live_dir/bin/osmap" \
		OSMAP_V6_SERVE_ENV_PATH="$live_dir/etc/osmap-serve.env" \
		OSMAP_V6_SERVE_LOG_PATH="$live_dir/log/serve.log" \
		OSMAP_V6_HELPER_LOG_PATH="$live_dir/log/helper.log" \
		OSMAP_V6_HELPER_SOCKET_PATH="$live_dir/run/mailbox-helper.sock" \
		OSMAP_V6_BINARY_BACKUP_DIR="$live_dir/bin" \
		OSMAP_V6_ENV_BACKUP_DIR="$live_dir/etc" \
		sh "$validator" --report "$report" "$@"
}

sh -n "$validator"
run_validator "$tmp_dir/good.txt" > "$tmp_dir/good.out"
grep -Fxq 'result=v6_production_readiness_passed' "$tmp_dir/good.txt"
grep -Fxq 'service_state=passed' "$tmp_dir/good.txt"
grep -Fxq 'invalid_host_421=passed' "$tmp_dir/good.txt"
grep -Fxq 'rollback_unit=passed' "$tmp_dir/good.txt"

if OSMAP_TEST_SERVICE_RC=1 run_validator "$tmp_dir/service-fail.txt" > "$tmp_dir/service-fail.out" 2>&1; then
	echo "expected missing service state to fail" >&2
	exit 1
fi
grep -Fxq 'service_state=failed' "$tmp_dir/service-fail.txt"

if OSMAP_TEST_INVALID_CODE=200 run_validator "$tmp_dir/host-fail.txt" > "$tmp_dir/host-fail.out" 2>&1; then
	echo "expected invalid Host behavior to fail" >&2
	exit 1
fi
grep -Fxq 'invalid_host_421=failed' "$tmp_dir/host-fail.txt"

rm "$live_dir/etc/osmap-serve.env.pre-fixture"
if run_validator "$tmp_dir/rollback-fail.txt" > "$tmp_dir/rollback-fail.out" 2>&1; then
	echo "expected missing rollback artifact to fail" >&2
	exit 1
fi
grep -Fxq 'rollback_unit=failed' "$tmp_dir/rollback-fail.txt"

if grep -Eiq 'password=|totp(_code)?=|csrf_token=|osmap_session=|set-cookie:' "$tmp_dir/good.txt"; then
	echo "production report contained a forbidden secret marker" >&2
	exit 1
fi

echo "V6 production readiness validator regression checks passed"
