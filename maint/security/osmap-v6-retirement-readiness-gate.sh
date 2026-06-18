#!/bin/sh

set -eu

repo_root=${OSMAP_V6_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

: "${OSMAP_V6_V4_GATE:=maint/security/osmap-v4-hostile-assurance-gate.sh}"
: "${OSMAP_V6_V5_GATE:=maint/security/osmap-v5-boundary-gate.sh}"
: "${OSMAP_V6_TRACE_DIR:=docs/V6_TRACES}"
: "${OSMAP_V6_PRODUCTION_REPORT:=maint/live/latest-host-v6-production-readiness-report.txt}"
: "${OSMAP_V6_REHEARSAL_REPORT:=maint/live/latest-host-v6-retirement-rehearsal-report.txt}"
: "${OSMAP_V6_OBSERVABILITY_REPORT:=maint/live/latest-host-v6-observability-report.txt}"
: "${OSMAP_V6_RESILIENCE_REPORT:=maint/live/latest-host-v6-resource-resilience-report.txt}"
: "${OSMAP_V6_CLOSEOUT_EVIDENCE:=docs/V6_CLOSEOUT_EVIDENCE.md}"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V6 closeout input: $path" >&2
		exit 1
	fi
}

require_marker() {
	path=$1
	marker=$2
	if ! grep -Fxq "$marker" "$path"; then
		echo "error: missing V6 report marker in $path: $marker" >&2
		exit 1
	fi
}

for path in \
	docs/V6_DEFINITION.md \
	docs/V6_ACCEPTANCE_CRITERIA.md \
	docs/V6_ROADMAP.md \
	docs/V6_SECURITY_GATES.md \
	docs/V6_RELEASE_OPERATOR_HANDOFF.md \
	src/session.rs \
	src/draft.rs \
	src/openbsd.rs \
	maint/security/osmap-v6-evidence-archive.sh \
	"$OSMAP_V6_PRODUCTION_REPORT" \
	"$OSMAP_V6_REHEARSAL_REPORT" \
	"$OSMAP_V6_OBSERVABILITY_REPORT" \
	"$OSMAP_V6_RESILIENCE_REPORT" \
	"$OSMAP_V6_CLOSEOUT_EVIDENCE"
do
	require_file "$path"
done

for source_requirement in \
	"src/draft.rs:DraftSourceAttachments" \
	"src/draft.rs:source_attachment_count" \
	"src/draft.rs:source_mailbox_hex"
do
	path=${source_requirement%%:*}
	text=${source_requirement#*:}
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V6 draft-source source requirement in $path: $text" >&2
		exit 1
	fi
done

for source_requirement in \
	"src/session.rs:SESSION_LOCK_FILE" \
	"src/session.rs:with_exclusive_lock" \
	"src/openbsd.rs:advisory_file_lock_exclusive"
do
	path=${source_requirement%%:*}
	text=${source_requirement#*:}
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V6 session-locking source requirement in $path: $text" >&2
		exit 1
	fi
done

slice=0
while [ "$slice" -le 9 ]; do
	slice_id=$(printf '%02d' "$slice")
	if ! find "$OSMAP_V6_TRACE_DIR" -maxdepth 1 -type f \
		-name "SLICE_${slice_id}_*.md" -size +0c | grep -q .; then
		echo "error: missing V6 trace for slice $slice_id" >&2
		exit 1
	fi
	slice=$((slice + 1))
done

sh "$OSMAP_V6_V4_GATE"
sh "$OSMAP_V6_V5_GATE"

for marker in \
	"result=v6_production_readiness_passed" \
	"valid_host_health=passed" \
	"invalid_host_421=passed" \
	"service_state=passed" \
	"rollback_unit=passed" \
	"log_paths=passed" \
	"backend_public_exposure=not_detected" \
	"secrets_redacted=passed"
do
	require_marker "$OSMAP_V6_PRODUCTION_REPORT" "$marker"
done

for marker in \
	"result=v6_retirement_rehearsal_passed" \
	"roundcube_fallback_used=no" \
	"native_clients_unchanged=yes" \
	"underlying_mail_stack_unchanged=yes" \
	"secrets_redacted=passed"
do
	require_marker "$OSMAP_V6_REHEARSAL_REPORT" "$marker"
done

for marker in \
	"result=v6_observability_passed" \
	"auth_events=passed" \
	"session_events=passed" \
	"send_events=passed" \
	"boundary_events=passed" \
	"redaction=passed" \
	"operator_review=passed"
do
	require_marker "$OSMAP_V6_OBSERVABILITY_REPORT" "$marker"
done

for marker in \
	"result=v6_resource_resilience_passed" \
	"health_under_pressure=passed" \
	"budget_or_timeout_boundary=passed" \
	"malformed_request_boundary=passed" \
	"recovery=passed" \
	"redaction=passed"
do
	require_marker "$OSMAP_V6_RESILIENCE_REPORT" "$marker"
done

python3 - \
	"$OSMAP_V6_PRODUCTION_REPORT" \
	"$OSMAP_V6_REHEARSAL_REPORT" \
	"$OSMAP_V6_OBSERVABILITY_REPORT" \
	"$OSMAP_V6_RESILIENCE_REPORT" \
	"$OSMAP_V6_CLOSEOUT_EVIDENCE" <<'PY'
import re
import sys
from pathlib import Path

patterns = {
    "raw password assignment": re.compile(r"(?im)^\s*password\s*=\s*\S+"),
    "raw TOTP assignment": re.compile(r"(?im)^\s*totp(?:_code)?\s*=\s*\d{6,8}\s*$"),
    "raw CSRF assignment": re.compile(r"(?im)^\s*csrf_token\s*=\s*(?!\[?redacted\]?\s*$)\S+"),
    "raw OSMAP cookie": re.compile(r"(?i)osmap_session=[A-Za-z0-9._~+/=-]{16,}"),
    "raw Set-Cookie header": re.compile(r"(?im)^set-cookie\s*:"),
    "private key block": re.compile(r"BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY"),
    "raw mailbox body marker": re.compile(r"(?im)^(?:raw_)?mailbox_body\s*="),
    "raw attachment body marker": re.compile(r"(?im)^(?:raw_)?attachment_body\s*="),
}

errors = []
for name in sys.argv[1:]:
    path = Path(name)
    text = path.read_text(encoding="utf-8")
    for label, pattern in patterns.items():
        if pattern.search(text):
            errors.append(f"{path}: {label}")

if errors:
    for error in errors:
        print(f"error: forbidden V6 evidence content: {error}", file=sys.stderr)
    raise SystemExit(1)
PY

echo "V6 retirement readiness gate passed"
