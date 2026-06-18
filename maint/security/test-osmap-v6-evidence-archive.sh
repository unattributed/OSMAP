#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
archiver="$repo_root/maint/security/osmap-v6-evidence-archive.sh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-archive.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

fixture="$tmp_dir/repo"
mkdir -p "$fixture/docs/V6_TRACES" "$fixture/maint/live"
for relative in \
	docs/V6_DEFINITION.md \
	docs/V6_ACCEPTANCE_CRITERIA.md \
	docs/V6_ROADMAP.md \
	docs/V6_SECURITY_GATES.md \
	docs/V6_CLOSEOUT_EVIDENCE.md \
	docs/V6_RELEASE_OPERATOR_HANDOFF.md \
	docs/V6_RESOURCE_RESILIENCE_EVIDENCE.md \
	docs/V4_CLOSEOUT_EVIDENCE.md \
	docs/V4_SECURITY_CLAIM_MATRIX.md \
	docs/V5_BOUNDARY_HARDENING_EVIDENCE.md \
	docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md \
	maint/live/latest-host-v6-production-readiness-report.txt \
	maint/live/latest-host-v6-retirement-rehearsal-report.txt \
	maint/live/latest-host-v6-observability-report.txt \
	maint/live/latest-host-v6-resource-resilience-report.txt
do
	mkdir -p "$fixture/$(dirname "$relative")"
	printf 'public-safe fixture\n' > "$fixture/$relative"
done

slice=0
while [ "$slice" -le 9 ]; do
	printf 'fixture trace\n' > "$fixture/docs/V6_TRACES/SLICE_$(printf '%02d' "$slice")_FIXTURE.md"
	slice=$((slice + 1))
done

cat > "$tmp_dir/pass-gate.sh" <<'EOF'
#!/bin/sh
printf '%s\n' 'V6 retirement readiness gate passed'
EOF
chmod +x "$tmp_dir/pass-gate.sh"

run_archiver() {
	OSMAP_V6_ARCHIVE_REPO_ROOT="$fixture" \
	OSMAP_V6_ARCHIVE_PATH="$tmp_dir/evidence.tar.gz" \
	OSMAP_V6_ARCHIVE_CHECKSUM_PATH="$tmp_dir/evidence.tar.gz.sha256" \
	OSMAP_V6_ARCHIVE_GATE="$tmp_dir/pass-gate.sh" \
	sh "$archiver"
}

sh -n "$archiver"
run_archiver > "$tmp_dir/pass.out"
test -s "$tmp_dir/evidence.tar.gz"
test -s "$tmp_dir/evidence.tar.gz.sha256"
tar -tzf "$tmp_dir/evidence.tar.gz" |
	grep -Fq 'osmap-v6-closeout-evidence/v6-retirement-readiness-gate.txt'
tar -tzf "$tmp_dir/evidence.tar.gz" |
	grep -Fq 'osmap-v6-closeout-evidence/docs/V6_TRACES/SLICE_09_FIXTURE.md'

printf '%s\n' 'password=fixture-secret' >> "$fixture/docs/V6_CLOSEOUT_EVIDENCE.md"
if run_archiver > "$tmp_dir/secret.out" 2>&1; then
	echo "expected secret-bearing archive input to fail" >&2
	exit 1
fi
grep -Fq 'forbidden secret or content marker' "$tmp_dir/secret.out"

echo "V6 evidence archive regression checks passed"
