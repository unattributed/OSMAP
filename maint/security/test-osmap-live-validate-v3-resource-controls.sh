#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="${repo_root}/maint/live/osmap-live-validate-v3-resource-controls.ksh"

sh -n "${validator}"
test -x "${validator}"

grep -Fq 'OSMAP_MAILBOX_WORKER_BUDGET=1' "${validator}"
grep -Fq 'OSMAP_SEARCH_WORKER_BUDGET=1' "${validator}"
grep -Fq 'OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS=5' "${validator}"
grep -Fq 'mailbox_boundary_mode=local_helper_socket' "${validator}"

grep -Fq 'require_budget_event request_budget_acquired compose_source mailbox_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_released compose_source mailbox_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_acquired attachment_download mailbox_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_released attachment_download mailbox_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_acquired message_move mailbox_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_released message_move mailbox_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_acquired message_search search_workers' "${validator}"
grep -Fq 'require_budget_event request_budget_released message_search search_workers' "${validator}"

grep -Fq 'msg="attachment download completed through mailbox helper"' "${validator}"
grep -Fq 'secret_review=No passwords, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.' "${validator}"
grep -Fq 'grep -Fq "${SESSION_TOKEN}" "${REPORT_PATH}"' "${validator}"
grep -Fq 'grep -Fq "${CSRF_TOKEN}" "${REPORT_PATH}"' "${validator}"

echo "live V3 resource-control validator regression checks passed"
