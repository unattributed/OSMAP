#!/bin/sh

set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
validator="${repo_root}/maint/live/osmap-live-validate-v4-hostile-content.ksh"

sh -n "${validator}"
test -x "${validator}"

grep -Fq 'osmap_v4_hostile_content_result' "${validator}"
grep -Fq 'v4_hostile_content_live_proof_passed' "${validator}"
grep -Fq 'OSMAP_OPENBSD_CONFINEMENT_MODE=enforce' "${validator}"
grep -Fq 'mailbox-helper-grant.key' "${validator}"

grep -Fq 'JaVaScRiPt:alert(1)' "${validator}"
grep -Fq '&#x6a;avascript:alert(1)' "${validator}"
grep -Fq 'blob:https://example.com/id' "${validator}"
grep -Fq 'vbscript:msgbox(1)' "${validator}"
grep -Fq 'file:///etc/passwd' "${validator}"
grep -Fq 'autofocus onfocus' "${validator}"
grep -Fq 'srcdoc' "${validator}"
grep -Fq '<video poster=' "${validator}"
grep -Fq 'image/svg+xml' "${validator}"
grep -Fq 'application/javascript' "${validator}"

grep -Fq 'hostile_html_destination_disclosure_css' "${validator}"
grep -Fq 'hostile_html_blob_scheme' "${validator}"
grep -Fq 'hostile_html_vbscript_scheme' "${validator}"
grep -Fq 'hostile_html_file_scheme' "${validator}"
grep -Fq 'hostile_html_autofocus_payload' "${validator}"
grep -Fq 'hostile_html_form_action_payload' "${validator}"
grep -Fq 'hostile_html_input_secret_payload' "${validator}"
grep -Fq '${label}_octet_stream' "${validator}"
grep -Fq 'assert_attachment_octet_stream "html_attachment"' "${validator}"
grep -Fq 'assert_attachment_octet_stream "svg_attachment"' "${validator}"
grep -Fq 'assert_attachment_octet_stream "script_attachment"' "${validator}"
grep -Fq 'X-Content-Type-Options: nosniff' "${validator}"

grep -Fq 'grep -Fq "${forbidden}" "${REPORT_PATH}"' "${validator}"
grep -Fq 'No password, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.' "${validator}"

echo "live V4 hostile-content validator regression checks passed"
