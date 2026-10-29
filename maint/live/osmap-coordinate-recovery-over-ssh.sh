#!/usr/bin/env bash
# D04 operator recovery: human identity decision, real containment/revocation,
# one guarded factor replacement and explicit reconciliation. Never signs.
set -euo pipefail
umask 077
COORDINATOR_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=maint/live/osmap-rotate-totp-over-ssh.sh
source "${COORDINATOR_DIR}/osmap-rotate-totp-over-ssh.sh"

coordinator_usage() {
    printf '%s\n' 'usage: osmap-coordinate-recovery-over-ssh.sh --request|--status|--dry-run|--recover ACCOUNT --host HOST --expected-hostname FQDN [--approval FILE --signature FILE] [--controlled-rehearsal]' >&2
    return 2
}

coordinator_native() {
    local host="$1" verb="$2" payload="$3"
    case "${verb}" in begin|status|prepare-factor|reconcile) ;; *) return 2 ;; esac
    # One SSH attempt. A transport failure after dispatch is uncertain; callers
    # preserve containment and never repeat a native mutation automatically.
    printf '%s\n' "${payload}" | timeout 100 ssh "${SSH_OPTS[@]}" "${host}" \
        doas -n /usr/local/libexec/osmap/account-recovery "${verb}"
}

coordinator_status() {
    local account="$1" host="$2" hostname="$3" payload
    rotation_host_check "${host}" "${hostname}" || return 1
    payload="$(python3 -c 'import json,sys;print(json.dumps(dict(schema="osmap-account-recovery-v1",account=sys.argv[1])))' "${account}")" || return 1
    coordinator_native "${host}" status "${payload}"
}

coordinator_identity() {
    local account="$1" host="$2" hostname="$3" digest="$4" epoch="$5"
    local -a mode=()
    [[ "${COORDINATOR_REHEARSAL}" != true ]] || mode+=(--controlled-rehearsal)
    python3 "${COORDINATOR_DIR}/osmap-totp-recovery-approval.py" --coordinator \
        --approval "${COORDINATOR_APPROVAL}" --signature "${COORDINATOR_SIGNATURE}" \
        --account "${account}" --host "${host}" --expected-hostname "${hostname}" \
        --digest "${digest}" --epoch "${epoch}" "${mode[@]}"
}

coordinator_authorize() {
    local account="$1" hostname="$2" case_id="$3" answer
    [[ -r /dev/tty && -w /dev/tty ]] || return 1
    {
        printf '\nRecovery case %s for %s on %s.\n' "${case_id}" "${account}" "${hostname}"
        printf '%s\n' 'Independent human identity authorization is required.' \
            'This operation contains OSMAP access, revokes account browser sessions and replaces the factor.' \
            'It does not reset the password or claim termination of existing IMAP/SMTP connections.' \
            'Failures before release retain containment; interrupted release requires read-only reconciliation of UNKNOWN access state.' \
            'No automatic retry or old-factor restore. Suspected account compromise requires separate mail containment and manual review.'
        [[ "${COORDINATOR_REHEARSAL}" != true ]] || printf '%s\n' 'Controlled test custody only: no real-user identity qualification.'
        printf 'Type exactly: RECOVER %s ON %s REQUEST %s\n' "${account}" "${hostname}" "${case_id}"
    } > /dev/tty
    IFS= read -r -p 'Authorization: ' answer < /dev/tty || return 1
    [[ "${answer}" == "RECOVER ${account} ON ${hostname} REQUEST ${case_id}" ]]
}

coordinator_pending() {
    printf '%s\n' 'ACCOUNT_RECOVERY=INCOMPLETE' 'automatic_mutation_retry=false' \
        'containment_release=UNKNOWN' 'manual_reconciliation_required=true'
    return 24
}

coordinator_prebegin_refused() {
    # Native/SSH text can contain private data. Retain only a fixed cause and
    # bounded stream accounting; this path has not dispatched native begin.
    local phase="$1" status="$2" observation="${3:-}"
    printf '%s' "${observation}" | python3 -c 'import hashlib,json,sys
phase,status=sys.argv[1:];digest=hashlib.sha256();size=0
for chunk in iter(lambda:sys.stdin.buffer.read(65536),b""):
 size+=len(chunk);digest.update(chunk)
causes={"candidate_material":"CANDIDATE_MATERIAL_REFUSED","candidate_digest":"CANDIDATE_DIGEST_REFUSED","factor_snapshot":"FACTOR_SNAPSHOT_REFUSED","factor_comparison":"CURRENT_FACTOR_CHANGED","identity_recheck":"IDENTITY_RECHECK_REFUSED","identity_comparison":"IDENTITY_DECISION_CHANGED"}
print(json.dumps(dict(schema="osmap-account-recovery-prebegin-refusal-v1",phase=phase,cause=causes[phase],exit=int(status),observation_bytes=size,observation_sha256=digest.hexdigest(),native_begin_dispatched=False,automatic_mutation_retry=False),separators=(",",":")),file=sys.stderr)' "${phase}" "${status}"
    return 1
}

coordinator_result() {
    local verb="$1" account="$2" case_id="$3" epoch="$4" digest="$5"
    python3 -c 'import json,sys
try:
 v=json.load(sys.stdin);verb,account,case,epoch,digest=sys.argv[1:];epoch=int(epoch)
 state,stage,wanted_epoch=("active","reconciled",epoch+1) if verb=="reconcile" else ("pending","sessions_revoked" if verb=="begin" else "factor_replacement",epoch)
 ok=v.get("schema")=="osmap-account-recovery-v1" and v.get("account")==account and v.get("case_id")==case and type(v.get("epoch")) is int and v["epoch"]==wanted_epoch and v.get("state")==state and v.get("case_state")==stage and v.get("existing_factor_sha256")==digest and v.get("failure") is None and v.get("session_failure") is None
except (ValueError,KeyError,TypeError,RecursionError):ok=False
raise SystemExit(0 if ok else 1)' "${verb}" "${account}" "${case_id}" "${epoch}" "${digest}"
}

coordinator_release_authorize() {
    local account="$1" hostname="$2" case_id="$3" answer
    [[ -r /dev/tty && -w /dev/tty ]] || return 1
    {
        printf '\nReplacement factor readback matches recovery case %s.\n' "${case_id}"
        printf '%s\n' 'Reconciliation will independently verify archived/active factor and session state before releasing OSMAP access.'
        printf 'Type exactly: RECONCILE %s ON %s REQUEST %s\n' "${account}" "${hostname}" "${case_id}"
    } > /dev/tty
    IFS= read -r -p 'Reconciliation: ' answer < /dev/tty || return 1
    [[ "${answer}" == "RECONCILE ${account} ON ${hostname} REQUEST ${case_id}" ]]
}

coordinator_run() {
    local account="$1" host="$2" hostname="$3" mutation="$4"
    local status digest epoch native verified case_id current new_digest stamp output secret runtime_paths candidate_rc
    status="$(coordinator_status "${account}" "${host}" "${hostname}")" || return 1
    current="$(python3 -c 'import json,sys,re
v=json.load(sys.stdin)
if v.get("schema")!="osmap-account-recovery-v1" or v.get("account")!=sys.argv[1] or v.get("state")!="active" or v.get("case_state") not in (None,"reconciled"): raise SystemExit(1)
e=v.get("epoch");d=v.get("existing_factor_sha256")
if type(e) is not int or not 0<=e<2**53 or not isinstance(d,str) or not re.fullmatch("[0-9a-f]{64}",d): raise SystemExit(1)
print(str(e)+" "+d)' "${account}" <<<"${status}")" || return 1
    read -r epoch digest <<<"${current}"
    runtime_paths="$(python3 -c 'import json,sys,re
v=json.load(sys.stdin).get("runtime_paths",{});p=[v.get("factor_directory"),v.get("revoked_directory")]
if any(not isinstance(x,str) or not re.fullmatch("/[A-Za-z0-9_/-]+",x) or x=="/" or x.endswith("/") or "//" in x for x in p) or p[0]==p[1]:raise SystemExit(1)
print(" ".join(p))' <<<"${status}")" || return 1
    read -r SECRET_DIR REVOKED_DIR <<<"${runtime_paths}"
    native="$(coordinator_identity "${account}" "${host}" "${hostname}" "${digest}" "${epoch}")" || return 1
    case_id="$(python3 -c 'import json,sys;print(json.load(sys.stdin)["case_id"])' <<<"${native}")" || return 1
    [[ "${mutation}" == true ]] || {
        printf '%s\n' 'COORDINATOR_DRY_RUN=PASS' 'recovery_mutation_performed=false' \
            'identity_signature_verified=true' 'containment_and_sessions_not_yet_performed=true'
        return 0
    }
    require_command qrencode || return 1
    prepare_enrollment_material "${account}" || return 1
    show_and_verify_enrollment "${account}" || return 1
    coordinator_authorize "${account}" "${hostname}" "${case_id}" || return 1
    secret="$(<"${SECRET_FILE}")" || { coordinator_prebegin_refused candidate_material "$?"; return 1; }
    printf '# %s\nsecret=%s\n' "${account}" "${secret}" > "${WORK_ROOT}/candidate.totp" || { candidate_rc=$?; unset secret; coordinator_prebegin_refused candidate_material "${candidate_rc}"; return 1; }
    unset secret
    new_digest="$(sha256sum "${WORK_ROOT}/candidate.totp" 2>&1 | awk '{print $1}')" || { coordinator_prebegin_refused candidate_digest "$?" "${new_digest}"; return 1; }
    [[ "${new_digest}" =~ ^[0-9a-f]{64}$ && "${new_digest}" != "${digest}" ]] || { coordinator_prebegin_refused candidate_digest 1; return 1; }
    # Revalidate signature/time/current factor after private interaction. Never
    # invent the legacy tool's external containment/session-attestation booleans.
    current="$(rotation_snapshot "${account}" "${host}" "${hostname}" 2>&1)" || { coordinator_prebegin_refused factor_snapshot "$?" "${current}"; return 1; }
    [[ "${current}" == "${digest}" ]] || { coordinator_prebegin_refused factor_comparison 1 "${current}"; return 1; }
    verified="$(coordinator_identity "${account}" "${host}" "${hostname}" "${digest}" "${epoch}" 2>&1)" || { coordinator_prebegin_refused identity_recheck "$?" "${verified}"; return 1; }
    [[ "${verified}" == "${native}" ]] || { coordinator_prebegin_refused identity_comparison 1 "${verified}"; return 1; }
    if ! output="$(coordinator_native "${host}" begin "${native}")"; then coordinator_pending; return 24; fi
    if ! coordinator_result begin "${account}" "${case_id}" "${epoch}" "${digest}" <<<"${output}"; then
        coordinator_pending; return 24
    fi
    stamp="$(date -u '+%Y%m%dT%H%M%SZ')" || { coordinator_pending; return 24; }
    native="$(python3 -c 'import json,sys;v=json.load(sys.stdin);v.update(replacement_factor_sha256=sys.argv[1],revoke_stamp=sys.argv[2]);print(json.dumps(v,separators=(",",":")))' "${new_digest}" "${stamp}" <<<"${native}")" || { coordinator_pending; return 24; }
    # These opaque/digest-only fields support explicit later reconciliation.
    printf '%s\n' "recovery_case_id=${case_id}" "replacement_factor_sha256=${new_digest}" "revoke_stamp=${stamp}"
    if ! output="$(coordinator_native "${host}" prepare-factor "${native}")"; then coordinator_pending; return 24; fi
    if ! coordinator_result prepare-factor "${account}" "${case_id}" "${epoch}" "${digest}" <<<"${output}"; then
        coordinator_pending; return 24
    fi
    if ! output="$(rotation_revoke "${account}" "${host}" "${digest}" "${stamp}")"; then coordinator_pending; return 24; fi
    if ! grep -Fxq 'TOTP_REVOCATION=PASS' <<<"${output}" ||
       ! grep -Fxq 'active_factor_absent=true' <<<"${output}" ||
       ! grep -Fxq 'revoked_factor_preserved=true' <<<"${output}" ||
       ! grep -Fxq "revoked_factor_sha256=${digest}" <<<"${output}"; then coordinator_pending; return 24; fi
    if ! output="$(remote_provision "${account}" "${host}" "${WORK_ROOT}/candidate.totp" "${new_digest}")"; then coordinator_pending; return 24; fi
    grep -Fxq 'TOTP_PROVISIONING=PASS' <<<"${output}" || { coordinator_pending; return 24; }
    current="$(rotation_snapshot "${account}" "${host}" "${hostname}")" || { coordinator_pending; return 24; }
    [[ "${current}" == "${new_digest}" ]] || { coordinator_pending; return 24; }
    coordinator_release_authorize "${account}" "${hostname}" "${case_id}" || { coordinator_pending; return 24; }
    if ! output="$(coordinator_native "${host}" reconcile "${native}")"; then coordinator_pending; return 24; fi
    if ! coordinator_result reconcile "${account}" "${case_id}" "${epoch}" "${new_digest}" <<<"${output}"; then
        coordinator_pending; return 24
    fi
    if [[ "${COORDINATOR_REHEARSAL}" == true ]]; then
        printf '%s\n' 'ACCOUNT_RECOVERY_REHEARSAL=PASS' 'real_user_identity_verification=false'
    else
        printf '%s\n' 'ACCOUNT_RECOVERY=PASS'
    fi
    printf '%s\n' 'password_reset_performed=false' \
        'browser_session_revocation_performed=true' 'mail_connection_termination_qualified=false'
}

coordinator_main() {
    local operation='' account='' host='' hostname='' status epoch digest
    local COORDINATOR_APPROVAL='' COORDINATOR_SIGNATURE='' COORDINATOR_REHEARSAL=false
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --request|--status|--dry-run|--recover) [[ -z "${operation}" ]] || return 2; operation="$1"; shift ;;
            --controlled-rehearsal) [[ "${COORDINATOR_REHEARSAL}" == false ]] || return 2; COORDINATOR_REHEARSAL=true; shift ;;
            --host|--expected-hostname|--approval|--signature)
                [[ "$#" -ge 2 && -n "$2" ]] || return 2
                case "$1" in
                    --host) [[ -z "${host}" ]] || return 2; host="$2" ;;
                    --expected-hostname) [[ -z "${hostname}" ]] || return 2; hostname="$2" ;;
                    --approval) [[ -z "${COORDINATOR_APPROVAL}" ]] || return 2; COORDINATOR_APPROVAL="$2" ;;
                    --signature) [[ -z "${COORDINATOR_SIGNATURE}" ]] || return 2; COORDINATOR_SIGNATURE="$2" ;;
                esac; shift 2 ;;
            -*) coordinator_usage; return 2 ;;
            *) [[ -z "${account}" ]] || return 2; account="$1"; shift ;;
        esac
    done
    [[ -n "${operation}" && -n "${account}" && -n "${host}" && -n "${hostname}" ]] || { coordinator_usage; return 2; }
    rotation_validate "${account}" "${host}" "${hostname}" || return 2
    # Fixed native roots cannot safely compose with legacy environment overrides.
    [[ "${SECRET_DIR}" == /var/lib/osmap/secrets/totp && "${REVOKED_DIR}" == /var/lib/osmap/secrets/totp-revoked && "${RUNTIME_OWNER}" == _osmap && "${RUNTIME_GROUP}" == _osmap ]] || return 2
    if [[ "${COORDINATOR_REHEARSAL}" == true ]]; then
        [[ "${account}" == osmap-helper-validation@blackbagsecurity.com && "${host}" == 192.168.1.44 && "${hostname}" == obsd1.blackbagsecurity.com ]] || return 2
    fi
    require_command timeout || return 1
    if [[ "${operation}" == --status || "${operation}" == --request ]]; then
        [[ -z "${COORDINATOR_APPROVAL}" && -z "${COORDINATOR_SIGNATURE}" ]] || return 2
        status="$(coordinator_status "${account}" "${host}" "${hostname}")" || return 1
        if [[ "${operation}" == --status ]]; then printf '%s\n' "${status}"; return 0; fi
        read -r epoch digest < <(python3 -c 'import json,sys;v=json.load(sys.stdin);print(v["epoch"],v["existing_factor_sha256"])' <<<"${status}") || return 1
        local -a mode=()
        [[ "${COORDINATOR_REHEARSAL}" != true ]] || mode+=(--controlled-rehearsal)
        python3 "${COORDINATOR_DIR}/osmap-totp-recovery-approval.py" --coordinator --template \
            --account "${account}" --host "${host}" --expected-hostname "${hostname}" --digest "${digest}" --epoch "${epoch}" "${mode[@]}"
        return "$?"
    fi
    [[ -n "${COORDINATOR_APPROVAL}" && -n "${COORDINATOR_SIGNATURE}" ]] || return 2
    coordinator_run "${account}" "${host}" "${hostname}" "$([[ "${operation}" == --recover ]] && printf true || printf false)"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then coordinator_main "$@"; fi
