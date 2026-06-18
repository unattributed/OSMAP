#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="$repo_root/maint/live/osmap-live-validate-v6-resource-resilience.ksh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-resource-resilience.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

bin_dir="$tmp_dir/bin"
mkdir -p "$bin_dir"
cat > "$bin_dir/cargo" <<'EOF'
#!/bin/sh
printf '%s\n' 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out'
EOF
cat > "$bin_dir/curl" <<'EOF'
#!/bin/sh
output=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-o) output=$2; shift 2 ;;
		-w) shift 2 ;;
		-H|--max-time) shift 2 ;;
		-k|-s|-S|-ksS) shift ;;
		*) shift ;;
	esac
done
printf '%s\n' 'ok' > "$output"
printf '200'
EOF
cat > "$bin_dir/git" <<'EOF'
#!/bin/sh
printf '%s\n' 'cccccccccccccccccccccccccccccccccccccccc'
EOF
cat > "$bin_dir/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' 'mail.blackbagsecurity.com'
EOF
chmod +x "$bin_dir"/*

printf '%s\n' 'result=v6_production_readiness_passed' > "$tmp_dir/production.txt"
printf '%s\n' 'osmap_v3_resource_controls_result=passed' > "$tmp_dir/v3-resource.txt"
printf '%s\n' 'OSMAP V3 resource and timeout hardening evidence' > "$tmp_dir/v3-timeout.txt"

run_validator() {
	env \
		PATH="$bin_dir:$PATH" \
		OSMAP_V6_RESILIENCE_PRODUCTION_REPORT="$tmp_dir/production.txt" \
		OSMAP_V6_V3_RESOURCE_REPORT="$tmp_dir/v3-resource.txt" \
		OSMAP_V6_V3_TIMEOUT_EVIDENCE="$tmp_dir/v3-timeout.txt" \
		sh "$validator" --report "$1"
}

sh -n "$validator"
run_validator "$tmp_dir/pass.txt" > "$tmp_dir/pass.out"
grep -Fxq 'result=v6_resource_resilience_passed' "$tmp_dir/pass.txt"
grep -Fxq 'health_under_pressure=passed' "$tmp_dir/pass.txt"
grep -Fxq 'budget_or_timeout_boundary=passed' "$tmp_dir/pass.txt"
grep -Fxq 'malformed_request_boundary=passed' "$tmp_dir/pass.txt"
grep -Fxq 'recovery=passed' "$tmp_dir/pass.txt"
grep -Fxq 'redaction=passed' "$tmp_dir/pass.txt"

sh "$validator" --dry-run --report "$tmp_dir/dry-run.txt" > "$tmp_dir/dry-run.out"
grep -Fxq 'result=v6_resource_resilience_diagnostic_only' "$tmp_dir/dry-run.txt"
if grep -Fq '=passed' "$tmp_dir/dry-run.txt"; then
	echo "dry-run report must not contain passing closeout markers" >&2
	exit 1
fi

printf '%s\n' 'result=not_ready' > "$tmp_dir/production.txt"
if run_validator "$tmp_dir/missing.txt" > "$tmp_dir/missing.out" 2>&1; then
	echo "expected missing production readiness to fail" >&2
	exit 1
fi
grep -Fq 'production readiness report is not passed' "$tmp_dir/missing.out"

echo "V6 resource resilience validator regression checks passed"
