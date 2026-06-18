#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-launcher-log-capture.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fake_bin="${tmpdir}/fake-osmap"
cat > "$fake_bin" <<'EOF'
#!/bin/sh
mode="${1:-unknown}"
printf 'ts=1 level=warn category=auth action=login_denied msg="probe" submitted_username="probe@example.invalid" mode="%s"\n' "$mode" >&2
exit "${FAKE_OSMAP_EXIT_STATUS:-0}"
EOF
chmod 0755 "$fake_bin"

serve_env="${tmpdir}/serve.env"
cat > "$serve_env" <<EOF
OSMAP_LOG_DIR=${tmpdir}/var-log-osmap
EOF

helper_env="${tmpdir}/helper.env"
cat > "$helper_env" <<EOF
OSMAP_LOG_DIR=${tmpdir}/var-log-osmap
EOF

mkdir -p "${tmpdir}/var-log-osmap"

OSMAP_BIN="$fake_bin" \
OSMAP_ENV_FILE="$serve_env" \
	sh "${repo_root}/maint/openbsd/libexec/osmap-serve-run.ksh" serve

grep -Fq 'action=login_denied' "${tmpdir}/var-log-osmap/serve.log"
grep -Fq 'mode="serve"' "${tmpdir}/var-log-osmap/serve.log"
grep -Fq 'action=process_exited' "${tmpdir}/var-log-osmap/serve.log"
grep -Fq 'exit_status="0"' "${tmpdir}/var-log-osmap/serve.log"

set +e
FAKE_OSMAP_EXIT_STATUS=23 \
OSMAP_BIN="$fake_bin" \
OSMAP_ENV_FILE="$serve_env" \
	sh "${repo_root}/maint/openbsd/libexec/osmap-serve-run.ksh" serve
serve_status=$?
set -e

[ "$serve_status" -eq 23 ] || {
	printf 'expected serve launcher to preserve exit status 23, got %s\n' "$serve_status" >&2
	exit 1
}
grep -Fq 'action=process_exited' "${tmpdir}/var-log-osmap/serve.log"
grep -Fq 'exit_status="23"' "${tmpdir}/var-log-osmap/serve.log"

OSMAP_BIN="$fake_bin" \
OSMAP_ENV_FILE="$helper_env" \
	sh "${repo_root}/maint/openbsd/libexec/osmap-mailbox-helper-run.ksh" mailbox-helper

grep -Fq 'action=login_denied' "${tmpdir}/var-log-osmap/mailbox-helper.log"
grep -Fq 'mode="mailbox-helper"' "${tmpdir}/var-log-osmap/mailbox-helper.log"

echo "openbsd launcher log-capture regression checks passed"
