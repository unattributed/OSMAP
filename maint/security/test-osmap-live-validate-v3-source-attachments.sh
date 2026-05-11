#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="${repo_root}/maint/live/osmap-live-validate-v3-source-attachments.ksh"

sh -n "${validator}"
test -x "${validator}"

grep -Fq 'real_password_plus_totp_with_temporary_mailbox_hash' "${validator}"
grep -Fq 'OSMAP_MAILBOX_WORKER_BUDGET=1' "${validator}"
grep -Fq 'mailbox_boundary_mode=local_helper_socket' "${validator}"

grep -Fq 'include_original_attachment_1' "${validator}"
grep -Fq 'include_original_attachment_2' "${validator}"
grep -Fq 'source_mailbox' "${validator}"
grep -Fq 'source_uid' "${validator}"
grep -Fq 'selected_attachment_body_marker_preserved=yes' "${validator}"
grep -Fq 'rejected_cases_delivered=no' "${validator}"

grep -Fq 'duplicate_selection_status=%s' "${validator}"
grep -Fq 'tampered_mailbox_status=%s' "${validator}"
grep -Fq 'tampered_uid_status=%s' "${validator}"
grep -Fq 'tampered_part_status=%s' "${validator}"
grep -Fq 'missing_csrf_status=%s' "${validator}"
grep -Fq 'cross_origin_status=%s' "${validator}"
grep -Fq 'stale_source_status=%s' "${validator}"

grep -Fq 'action=request_budget_acquired' "${validator}"
grep -Fq 'route_class="original_attachment_send"' "${validator}"
grep -Fq 'action=http_send_original_attachment_selection_rejected' "${validator}"
grep -Fq 'action=http_send_original_attachment_fetch_failed' "${validator}"

grep -Fq 'grep -Fq "${forbidden}" "${REPORT_PATH}"' "${validator}"
grep -Fq 'No password, password hash, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.' "${validator}"

echo "live V3 source-attachment validator regression checks passed"
