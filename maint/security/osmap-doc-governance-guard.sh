#!/bin/sh
#
# Guard the project-governance invariants that define OSMAP's scope.

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

require_file() {
	path=$1
	if [ ! -f "$path" ]; then
		echo "missing required governance file: ${path#$repo_root/}" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "missing required governance text in ${path#$repo_root/}: $text" >&2
		exit 1
	fi
}

readme="${repo_root}/README.md"
charter="${repo_root}/docs/PROJECT_CHARTER.md"
program_baseline="${repo_root}/docs/PROGRAM_BASELINE.md"
v1_requirements="${repo_root}/docs/PRODUCT_REQUIREMENTS_V1.md"
v2_definition="${repo_root}/docs/V2_DEFINITION.md"
v3_definition="${repo_root}/docs/V3_DEFINITION.md"
v3_security_gates="${repo_root}/docs/V3_SECURITY_GATES.md"
v4_definition="${repo_root}/docs/V4_DEFINITION.md"
v4_security_gates="${repo_root}/docs/V4_SECURITY_GATES.md"
v4_closeout_evidence="${repo_root}/docs/V4_CLOSEOUT_EVIDENCE.md"
v4_release_handoff="${repo_root}/docs/V4_RELEASE_OPERATOR_HANDOFF.md"
v4_mime_ambiguity_evidence="${repo_root}/docs/V4_MIME_AMBIGUITY_EVIDENCE.md"
v4_closeout_guard="${repo_root}/maint/security/test-osmap-v4-closeout-evidence.sh"

require_file "$readme"
require_file "$charter"
require_file "$program_baseline"
require_file "$v1_requirements"
require_file "$v2_definition"
require_file "$v3_definition"
require_file "$v3_security_gates"
require_file "$v4_definition"
require_file "$v4_security_gates"
require_file "$v4_closeout_evidence"
require_file "$v4_release_handoff"
require_file "$v4_mime_ambiguity_evidence"
require_file "$v4_closeout_guard"

require_text "$readme" "The current release evidence is anchored by \`v4.0.0\`"
require_text "$readme" "evidence bundle commit \`59da020\`"
require_text "$readme" "assessed V4 code commit \`09a95b7\`"
require_text "$readme" "V4 does not claim rich-mail safety, malware prevention, attachment preview"
require_text "$readme" "any later code change must refresh V4 evidence"

require_text "$charter" "The project is not a mail-server replacement"
require_text "$charter" "not a general"
require_text "$charter" "groupware platform"
require_text "$charter" "Preserve IMAP and SMTP compatibility with the existing stack"
require_text "$charter" "Favor least privilege, reduced complexity, and high reviewability"
require_text "$charter" "Security takes priority over feature breadth"

require_text "$program_baseline" "replace Roundcube with a smaller, security-first, maintainable application"
require_text "$program_baseline" "preservation of compatibility with the existing mail stack"
require_text "$program_baseline" "A replacement that becomes a second complex platform would fail the project"

require_text "$v1_requirements" "Version 1 is constrained to a mail-only web access product"
require_text "$v1_requirements" "no plugin system in version 1"
require_text "$v1_requirements" "replacement of Postfix, Dovecot, nginx, MariaDB, or SOGo"

require_text "$v2_definition" "Dovecot and Postfix remain authoritative"
require_text "$v2_definition" "OSMAP stays a constrained browser"
require_text "$v2_definition" '`_osmap` must not become `vmail`'
require_text "$v2_definition" 'the request path must not depend on `doas`, root privileges, or broad host'
require_text "$v2_definition" "browser hardening must not weaken"

require_text "$v3_definition" "Version 3 is not acceptable if feature work outruns security evidence"
require_text "$v3_definition" "It does not exist to add contacts, calendars, plugins, groupware"
require_text "$v3_definition" "replacement of Postfix, Dovecot, nginx, PF, Rspamd, or the existing mail substrate"
require_text "$v3_definition" "all Version 2 gates remain required"
require_text "$v3_definition" "OSMAP remains a focused secure browser-mail access layer"

require_text "$v3_security_gates" "Release mode must fail"
require_text "$v3_security_gates" "Version 3 cannot pass by replacing, weakening, or silently skipping any of these gates"
require_text "$v3_security_gates" "Authenticated security tests must not be treated as complete unless credential and TOTP-dependent paths are actually exercised"
require_text "$v3_security_gates" "If a Version 3 feature passes ordinary functional tests but fails one of the security gates above, the feature remains incomplete"

require_text "$v4_definition" "Version 4 is a hostile-content safety release"
require_text "$v4_definition" "no-Javascript"
require_text "$v4_definition" "no-remote-load browser boundary"
require_text "$v4_definition" "remote message resources must not load automatically"
require_text "$v4_definition" "OSMAP remains a focused secure browser-mail access layer"

require_text "$v4_security_gates" "Version 4 cannot pass by replacing, weakening, or silently skipping any of these gates"
require_text "$v4_security_gates" "attacker-controlled mail cannot gain active browser execution"
require_text "$v4_security_gates" "It is not a substitute for the live-host proof at release closeout"
require_text "$v4_security_gates" "If a V4 change passes ordinary functional tests but fails one of the security gates above, the change remains incomplete"

require_text "$v4_closeout_evidence" "result=v4_hostile_content_live_proof_passed"
require_text "$v4_closeout_evidence" "The V4 hostile-content closeout evidence bundle is assembled"
require_text "$v4_closeout_evidence" "V3 Carry-Forward Evidence"
require_text "$v4_closeout_evidence" "Residual-Risk Statement"
require_text "$v4_closeout_evidence" "09a95b7"

require_text "$v4_release_handoff" 'GitHub release tag | `v4.0.0`'
require_text "$v4_release_handoff" 'Evidence bundle commit | `59da020`'
require_text "$v4_release_handoff" 'Assessed V4 code commit | `09a95b7`'
require_text "$v4_release_handoff" "OSMAP v4.0.0 is a hostile-content safety release"
require_text "$v4_release_handoff" "does not claim rich-mail safety, malware prevention, attachment preview safety, URL reputation"
require_text "$v4_release_handoff" "files may still be malicious after a user"
require_text "$v4_release_handoff" 'Any code change after `09a95b7` requires refreshed V4 evidence'

require_text "$v4_mime_ambiguity_evidence" "malformed, nested, suspicious, unsupported, and oversized MIME inputs"
require_text "$v4_mime_ambiguity_evidence" "product-code regression tests"
require_text "$v4_mime_ambiguity_evidence" 'This evidence is carried by the V4 assessed code commit `09a95b7`'
require_text "$v4_mime_ambiguity_evidence" '`v4.0.0` evidence bundle at `59da020`'

require_text "$v4_closeout_guard" "V4 closeout evidence checks passed"
require_text "$v4_closeout_guard" "v4_hostile_content_live_proof_passed"
require_text "$v4_closeout_guard" "V3 carry-forward"

echo "documentation governance guard passed"
