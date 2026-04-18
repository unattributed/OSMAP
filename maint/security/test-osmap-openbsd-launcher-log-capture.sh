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
EOF
chmod 0755 "$fake_bin"

serve_env="${tmpdir}/serve.env"
cat > "$serve_env" <<EOF
OSMAP_AUDIT_DIR=${tmpdir}/serve-audit
OSMAP_STDERR_LOG_PATH=${tmpdir}/serve-audit/serve.log
EOF

helper_env="${tmpdir}/helper.env"
cat > "$helper_env" <<EOF
OSMAP_AUDIT_DIR=${tmpdir}/helper-audit
OSMAP_STDERR_LOG_PATH=${tmpdir}/helper-audit/mailbox-helper.log
EOF

mkdir -p "${tmpdir}/serve-audit" "${tmpdir}/helper-audit"

OSMAP_BIN="$fake_bin" \
OSMAP_ENV_FILE="$serve_env" \
	sh "${repo_root}/maint/openbsd/libexec/osmap-serve-run.ksh" serve

grep -Fq 'action=login_denied' "${tmpdir}/serve-audit/serve.log"
grep -Fq 'mode="serve"' "${tmpdir}/serve-audit/serve.log"

OSMAP_BIN="$fake_bin" \
OSMAP_ENV_FILE="$helper_env" \
	sh "${repo_root}/maint/openbsd/libexec/osmap-mailbox-helper-run.ksh" mailbox-helper

grep -Fq 'action=login_denied' "${tmpdir}/helper-audit/mailbox-helper.log"
grep -Fq 'mode="mailbox-helper"' "${tmpdir}/helper-audit/mailbox-helper.log"

echo "openbsd launcher log-capture regression checks passed"
