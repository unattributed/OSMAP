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

reject_text() {
	path=$1
	text=$2
	if grep -Fq "$text" "$path"; then
		echo "stale or forbidden governance text in ${path#$repo_root/}: $text" >&2
		exit 1
	fi
}

readme="${repo_root}/README.md"
docs_index="${repo_root}/docs/README.md"
charter="${repo_root}/docs/PROJECT_CHARTER.md"
program_baseline="${repo_root}/docs/PROGRAM_BASELINE.md"
known_limitations="${repo_root}/docs/KNOWN_LIMITATIONS.md"
current_project_status="${repo_root}/docs/CURRENT_PROJECT_STATUS.md"
risk_register="${repo_root}/docs/RISK_REGISTER.md"
current_architecture="${repo_root}/docs/CURRENT_SYSTEM_ARCHITECTURE.md"
deployment_openbsd="${repo_root}/docs/DEPLOYMENT_OPENBSD.md"
faq_operators="${repo_root}/docs/FAQ_OPERATORS.md"
v1_requirements="${repo_root}/docs/PRODUCT_REQUIREMENTS_V1.md"
v2_definition="${repo_root}/docs/V2_DEFINITION.md"
v3_definition="${repo_root}/docs/V3_DEFINITION.md"
v3_security_gates="${repo_root}/docs/V3_SECURITY_GATES.md"
v4_definition="${repo_root}/docs/V4_DEFINITION.md"
v4_security_gates="${repo_root}/docs/V4_SECURITY_GATES.md"
v4_closeout_evidence="${repo_root}/docs/V4_CLOSEOUT_EVIDENCE.md"
v4_release_handoff="${repo_root}/docs/V4_RELEASE_OPERATOR_HANDOFF.md"
v4_mime_ambiguity_evidence="${repo_root}/docs/V4_MIME_AMBIGUITY_EVIDENCE.md"
v4_security_claim_matrix="${repo_root}/docs/V4_SECURITY_CLAIM_MATRIX.md"
v6_closeout_evidence="${repo_root}/docs/V6_CLOSEOUT_EVIDENCE.md"
v7_production_availability_closeout="${repo_root}/docs/V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md"
v9_production_convergence="${repo_root}/docs/V9_PRODUCTION_CONVERGENCE.md"
v9_release_candidate_closeout="${repo_root}/docs/V9_RELEASE_CANDIDATE_CLOSEOUT.md"
decision_log="${repo_root}/docs/DECISION_LOG.md"
v4_closeout_guard="${repo_root}/maint/security/test-osmap-v4-closeout-evidence.sh"

require_file "$readme"
require_file "$docs_index"
require_file "$charter"
require_file "$program_baseline"
require_file "$known_limitations"
require_file "$current_project_status"
require_file "$risk_register"
require_file "$current_architecture"
require_file "$deployment_openbsd"
require_file "$faq_operators"
require_file "$v1_requirements"
require_file "$v2_definition"
require_file "$v3_definition"
require_file "$v3_security_gates"
require_file "$v4_definition"
require_file "$v4_security_gates"
require_file "$v4_closeout_evidence"
require_file "$v4_release_handoff"
require_file "$v4_mime_ambiguity_evidence"
require_file "$v4_security_claim_matrix"
require_file "$v6_closeout_evidence"
require_file "$v7_production_availability_closeout"
require_file "$v9_production_convergence"
require_file "$v9_release_candidate_closeout"
require_file "$decision_log"
require_file "$v4_closeout_guard"

require_text "$readme" "## Current V13 status"
require_text "$readme" "V13 is the current reviewed production and assurance closeout."
require_text "$readme" "Final reviewed commit | \`7009b15322c4e7795c797c1387b403e0f4935adb\`"
require_text "$readme" "Live and staged binary SHA256 | \`333a417bf435ae74bfc2b7a9eebedeca1ad541cb527e2555fed408e11e24d963\`"
require_text "$readme" "Credentialed result | \`42 pass\`, \`0 fail\`, \`0 warning\`, \`0 skip\`, and \`4\` justified not-applicable results"
require_text "$readme" "V12 remains a non-cryptographic OpenPGP foundation."
require_text "$readme" "The current release evidence is still bounded."
require_text "$readme" "V9 remains historical selected-cohort"
reject_text "$readme" "<!-- OSMAP:V9-SLICE5-V7-CLOSEOUT:START -->"
reject_text "$readme" "<!-- OSMAP:V9_STATUS:START -->"
reject_text "$readme" "Production convergence intake is open"
reject_text "$readme" "release-candidate status is not decided"
reject_text "$readme" "V9 hold-period proof remains required"
reject_text "$readme" "final V9 release-candidate gate remain open"

require_text "$docs_index" "13 completes WSTG assurance integrity, adversarial validation, credentialed"
require_text "$docs_index" "Use \`CURRENT_PROJECT_STATUS.md\` as the short current-state authority."
require_text "$docs_index" "\`V9_RELEASE_CANDIDATE_CLOSEOUT.md\`"
require_text "$docs_index" "\`V7_PRODUCTION_AVAILABILITY_CLOSEOUT.md\`"
require_text "$docs_index" "\`security/OSMAP_WSTG_DUE_DILIGENCE_REVIEW_2026_05_19.md\`"
require_text "$docs_index" "\`security/OSMAP_WSTG_SCENARIO_MATRIX_V42.md\`"
find "$repo_root/docs" -type f -name '*.md' | sed "s#^$repo_root/docs/##" | while IFS= read -r docs_path; do
	require_text "$docs_index" "\`$docs_path\`"
done

require_text "$known_limitations" "V9 Slice 6 later accepted the V6 selected-cohort/no-Roundcube closeout criteria"
require_text "$known_limitations" "The V9 release-candidate decision resolved"
require_text "$known_limitations" "This is a selected-cohort release-candidate decision"
reject_text "$known_limitations" "V9 still requires a"
reject_text "$known_limitations" "V9 has not yet produced"
reject_text "$known_limitations" "final V9 release-candidate gate remain open"

require_text "$current_project_status" "This document is the current public-safe status record for OSMAP."
require_text "$current_project_status" "V12 | OpenPGP foundation completed through Slice 14 closeout readiness."
require_text "$current_project_status" "V13 | WSTG assurance integrity and adversarial validation are completed and deployed."
require_text "$current_project_status" "V12 does not enable runtime cryptography."

require_text "$risk_register" "Selected-cohort Roundcube retirement expands beyond the bounded V9 evidence"
require_text "$risk_register" "Browser availability regresses after the V9 selected-cohort release-candidate decision"
reject_text "$risk_register" "Keep V7 production approval reopened"

require_text "$current_architecture" "This document is a historical baseline of the pre-OSMAP public-edge posture"
require_text "$current_architecture" "public HTTPS now serves OSMAP through nginx"
require_text "$deployment_openbsd" "Current Implemented Deployment Shape"
require_text "$deployment_openbsd" "mailbox helper boundary uses a Unix socket"
require_text "$faq_operators" "approved limited direct public browser exposure"

require_text "$v6_closeout_evidence" "Post-V9 Status Note"
require_text "$v6_closeout_evidence" "V9 release-candidate gate accepted the V6"
require_text "$v7_production_availability_closeout" "V9 release-candidate PASS decision"
require_text "$v9_production_convergence" "The final V9 gate later recorded a PASS decision"
require_text "$v9_production_convergence" "V6 selected-cohort/no-Roundcube closure and the final V9 release-candidate gate are reconciled"
require_text "$v9_release_candidate_closeout" "verdict: \`V6_SELECTED_COHORT_CLOSEOUT_SATISFIED\`"
reject_text "$v9_release_candidate_closeout" "verdict: \`V5\`"

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
require_text "$v4_security_gates" "Hostile corpus release gate"
require_text "$v4_security_gates" "osmap-v4-hostile-assurance-gate.sh"
require_text "$v4_security_gates" "If a V4 change passes ordinary functional tests but fails one of the security gates above, the change remains incomplete"

require_text "$v4_security_claim_matrix" "V4 cannot inherit the hostile-content containment claim"
require_text "$v4_security_claim_matrix" "tests/v4_hostile_assurance.rs"
require_text "$v4_security_claim_matrix" "maint/live/osmap-v4-hostile-assurance-report.json"

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

awk '
  /^## [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]($|,)/ {
    current = substr($2, 1, 10)
    if (last != "" && current < last) {
      printf "decision log dates must be oldest-to-newest: %s appears after %s at line %d\n", current, last, NR > "/dev/stderr"
      exit 1
    }
    last = current
  }
' "$decision_log"

echo "documentation governance guard passed"
