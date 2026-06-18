#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="$repo_root/maint/live/osmap-live-validate-v6-observability.ksh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-observability.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

bin_dir="$tmp_dir/bin"
mkdir -p "$bin_dir"
cat > "$bin_dir/doas" <<'EOF'
#!/bin/sh
exec "$@"
EOF
cat > "$bin_dir/stat" <<'EOF'
#!/bin/sh
printf '%s\n' '_osmap:_osmap:600'
EOF
cat > "$bin_dir/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' 'mail.blackbagsecurity.com'
EOF
cat > "$bin_dir/git" <<'EOF'
#!/bin/sh
printf '%s\n' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
EOF
chmod +x "$bin_dir"/*

cat > "$tmp_dir/serve.log" <<'EOF'
category=auth action=login_denied result=denied
category=auth action=second_factor_accepted result=accepted
category=session action=session_issued session_ref=abcdef1234567890
category=session action=session_revoked session_ref=abcdef1234567890
category=submission action=message_submitted recipient_count=1 attachment_count=0
category=http action=http_host_rejected result=denied
EOF
cat > "$tmp_dir/helper.log" <<'EOF'
category=mailbox action=mailbox_helper_started result=ready
EOF
printf 'invalid_host_421=passed\n' > "$tmp_dir/production.txt"

run_validator() {
	env \
		PATH="$bin_dir:$PATH" \
		OSMAP_V6_OBSERVABILITY_SERVE_LOG_PATH="$tmp_dir/serve.log" \
		OSMAP_V6_OBSERVABILITY_HELPER_LOG_PATH="$tmp_dir/helper.log" \
		OSMAP_V6_OBSERVABILITY_PRODUCTION_REPORT="$tmp_dir/production.txt" \
		OSMAP_V6_CAPACITY_EVIDENCE=negative_live_safe_not_triggered \
		OSMAP_V6_OBSERVABILITY_OPERATOR_REVIEW=passed \
		sh "$validator" --report "$1"
}

sh -n "$validator"
run_validator "$tmp_dir/pass.txt" > "$tmp_dir/pass.out"
grep -Fxq 'result=v6_observability_passed' "$tmp_dir/pass.txt"
grep -Fxq 'redaction=passed' "$tmp_dir/pass.txt"

cp "$tmp_dir/serve.log" "$tmp_dir/serve.good"
sed '/action=session_revoked/d' "$tmp_dir/serve.good" > "$tmp_dir/serve.log"
if run_validator "$tmp_dir/missing.txt" > "$tmp_dir/missing.out" 2>&1; then
	echo "expected missing session event to fail" >&2
	exit 1
fi
grep -Fq "session_revoked" "$tmp_dir/missing.out"
mv "$tmp_dir/serve.good" "$tmp_dir/serve.log"

printf '%s\n' 'password=fixture-secret' >> "$tmp_dir/serve.log"
if run_validator "$tmp_dir/secret.txt" > "$tmp_dir/secret.out" 2>&1; then
	echo "expected secret-bearing logs to fail" >&2
	exit 1
fi
grep -Fq "forbidden raw secret" "$tmp_dir/secret.out"

echo "V6 observability validator regression checks passed"
