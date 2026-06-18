#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
gate="$repo_root/maint/security/osmap-v6-retirement-readiness-gate.sh"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-gate.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/traces"
slice=0
while [ "$slice" -le 9 ]; do
	printf '# fixture trace\n' > "$tmp_dir/traces/SLICE_$(printf '%02d' "$slice")_FIXTURE.md"
	slice=$((slice + 1))
done

cat > "$tmp_dir/pass-gate.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$tmp_dir/pass-gate.sh"

cat > "$tmp_dir/production.txt" <<'EOF'
result=v6_production_readiness_passed
valid_host_health=passed
invalid_host_421=passed
service_state=passed
rollback_unit=passed
log_paths=passed
backend_public_exposure=not_detected
secrets_redacted=passed
EOF

cat > "$tmp_dir/rehearsal.txt" <<'EOF'
result=v6_retirement_rehearsal_passed
roundcube_fallback_used=no
native_clients_unchanged=yes
underlying_mail_stack_unchanged=yes
secrets_redacted=passed
EOF

cat > "$tmp_dir/observability.txt" <<'EOF'
result=v6_observability_passed
auth_events=passed
session_events=passed
send_events=passed
boundary_events=passed
redaction=passed
operator_review=passed
EOF

cat > "$tmp_dir/resilience.txt" <<'EOF'
result=v6_resource_resilience_passed
health_under_pressure=passed
budget_or_timeout_boundary=passed
malformed_request_boundary=passed
recovery=passed
redaction=passed
EOF

printf '# fixture closeout\n' > "$tmp_dir/closeout.md"

run_gate() {
	OSMAP_V6_V4_GATE="$tmp_dir/pass-gate.sh" \
	OSMAP_V6_V5_GATE="$tmp_dir/pass-gate.sh" \
	OSMAP_V6_TRACE_DIR="$tmp_dir/traces" \
	OSMAP_V6_PRODUCTION_REPORT="$tmp_dir/production.txt" \
	OSMAP_V6_REHEARSAL_REPORT="$tmp_dir/rehearsal.txt" \
	OSMAP_V6_OBSERVABILITY_REPORT="$tmp_dir/observability.txt" \
	OSMAP_V6_RESILIENCE_REPORT="$tmp_dir/resilience.txt" \
	OSMAP_V6_CLOSEOUT_EVIDENCE="$tmp_dir/closeout.md" \
	sh "$gate"
}

sh -n "$gate"
run_gate > "$tmp_dir/positive.out"
grep -Fq "V6 retirement readiness gate passed" "$tmp_dir/positive.out"

cp "$tmp_dir/rehearsal.txt" "$tmp_dir/rehearsal.good"
sed 's/roundcube_fallback_used=no/roundcube_fallback_used=yes/' \
	"$tmp_dir/rehearsal.good" > "$tmp_dir/rehearsal.txt"
if run_gate > "$tmp_dir/fallback.out" 2>&1; then
	echo "expected V6 gate to fail when Roundcube fallback was used" >&2
	exit 1
fi
grep -Fq "roundcube_fallback_used=no" "$tmp_dir/fallback.out"
mv "$tmp_dir/rehearsal.good" "$tmp_dir/rehearsal.txt"

cp "$tmp_dir/production.txt" "$tmp_dir/production.good"
sed '/service_state=passed/d' "$tmp_dir/production.good" > "$tmp_dir/production.txt"
if run_gate > "$tmp_dir/service.out" 2>&1; then
	echo "expected V6 gate to fail without service state evidence" >&2
	exit 1
fi
grep -Fq "service_state=passed" "$tmp_dir/service.out"
mv "$tmp_dir/production.good" "$tmp_dir/production.txt"

printf '%s\n' 'password=fixture-secret' >> "$tmp_dir/observability.txt"
if run_gate > "$tmp_dir/secret.out" 2>&1; then
	echo "expected V6 gate to fail for secret-bearing evidence" >&2
	exit 1
fi
grep -Fq "raw password assignment" "$tmp_dir/secret.out"

echo "V6 retirement readiness gate regression checks passed"
