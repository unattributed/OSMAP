#!/bin/sh

set -eu

repo_root=${OSMAP_V6_ARCHIVE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
archive_path=${OSMAP_V6_ARCHIVE_PATH:-"$repo_root/maint/live/osmap-v6-closeout-evidence.tar.gz"}
checksum_path=${OSMAP_V6_ARCHIVE_CHECKSUM_PATH:-"$archive_path.sha256"}
gate=${OSMAP_V6_ARCHIVE_GATE:-"$repo_root/maint/security/osmap-v6-retirement-readiness-gate.sh"}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-evidence-archive.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

staging="$tmp_dir/osmap-v6-closeout-evidence"
mkdir -p "$staging"

copy_required() {
	relative=$1
	source="$repo_root/$relative"
	if [ ! -s "$source" ]; then
		echo "error: missing V6 archive input: $relative" >&2
		exit 1
	fi
	mkdir -p "$staging/$(dirname "$relative")"
	cp "$source" "$staging/$relative"
}

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
	copy_required "$relative"
done

slice=0
while [ "$slice" -le 9 ]; do
	slice_id=$(printf '%02d' "$slice")
	trace=$(find "$repo_root/docs/V6_TRACES" -maxdepth 1 -type f \
		-name "SLICE_${slice_id}_*.md" -size +0c | head -1)
	if [ -z "$trace" ]; then
		echo "error: missing V6 archive trace for slice $slice_id" >&2
		exit 1
	fi
	copy_required "${trace#"$repo_root/"}"
	slice=$((slice + 1))
done

if ! sh "$gate" > "$staging/v6-retirement-readiness-gate.txt" 2>&1; then
	sed -n '1,80p' "$staging/v6-retirement-readiness-gate.txt" >&2
	echo "error: V6 gate failed; evidence archive was not created" >&2
	exit 1
fi

forbidden='password[[:space:]]*=|totp(_code)?[[:space:]]*=|csrf_token[[:space:]]*=|osmap_session=|set-cookie[[:space:]]*:|BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY|^(raw_)?mailbox_body[[:space:]]*=|^(raw_)?attachment_body[[:space:]]*='
if grep -ERiq "$forbidden" "$staging"; then
	echo "error: forbidden secret or content marker in V6 archive inputs" >&2
	exit 1
fi

mkdir -p "$(dirname "$archive_path")" "$(dirname "$checksum_path")"
tar -C "$tmp_dir" -czf "$archive_path.tmp" "$(basename "$staging")"
mv "$archive_path.tmp" "$archive_path"

if command -v sha256 >/dev/null 2>&1; then
	digest=$(sha256 -q "$archive_path")
elif command -v sha256sum >/dev/null 2>&1; then
	digest=$(sha256sum "$archive_path" | awk '{print $1}')
else
	echo "error: sha256 or sha256sum is required" >&2
	rm -f "$archive_path"
	exit 1
fi
printf '%s  %s\n' "$digest" "$(basename "$archive_path")" > "$checksum_path.tmp"
mv "$checksum_path.tmp" "$checksum_path"

echo "created V6 evidence archive: $archive_path"
echo "created V6 evidence checksum: $checksum_path"
