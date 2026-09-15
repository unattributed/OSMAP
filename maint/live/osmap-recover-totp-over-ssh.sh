#!/usr/bin/env bash
# Recovery requires a short-lived signed operator attestation plus an explicit
# terminal decision. This tool never signs approvals or authenticates a claimant.
set -euo pipefail
umask 077

RECOVERY_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=maint/live/osmap-rotate-totp-over-ssh.sh
source "${RECOVERY_DIR}/osmap-rotate-totp-over-ssh.sh"

recovery_usage() {
    printf '%s\n' 'usage: osmap-recover-totp-over-ssh.sh --request|--dry-run|--recover ACCOUNT --host HOST --expected-hostname FQDN [--approval FILE --signature FILE]' >&2
    return 2
}

recovery_approve_snapshot() {
    local account="$1" host="$2" hostname="$3" digest="$4" output approval_digest request_id
    output="$(python3 "${RECOVERY_DIR}/osmap-totp-recovery-approval.py" \
        --approval "${RECOVERY_APPROVAL}" --signature "${RECOVERY_SIGNATURE}" \
        --account "${account}" --host "${host}" --expected-hostname "${hostname}" --digest "${digest}")" || {
        printf '%s\n' 'ERROR: recovery approval refused; no recovery mutation attempted' >&2
        return 1
    }
    grep -Fxq 'RECOVERY_APPROVAL=PASS' <<<"${output}" || return 1
    approval_digest="$(awk -F= '/^approval_sha256=/{print $2}' <<<"${output}")"
    request_id="$(awk -F= '/^approval_request_id=/{print $2}' <<<"${output}")"
    [[ "${approval_digest}" =~ ^[0-9a-f]{64}$ && "${request_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || return 1
    if [[ -n "${RECOVERY_ACCEPTED_SHA}" && "${RECOVERY_ACCEPTED_SHA}" != "${approval_digest}" ]]; then
        printf '%s\n' 'ERROR: recovery approval changed during enrollment; no mutation attempted' >&2
        return 1
    fi
    RECOVERY_ACCEPTED_SHA="${approval_digest}"
    RECOVERY_REQUEST_ID="${request_id}"
    printf '%s\n' "${output}"
}

recovery_authorize() {
    local account="$1" host="$2" hostname="$3" answer
    [[ -r /dev/tty && -w /dev/tty ]] || return 1
    {
        printf '\nRecovery request %s for %s on %s (%s).\n' "${RECOVERY_REQUEST_ID}" "${account}" "${host}" "${hostname}"
        printf '%s\n' 'The signed approval attests independent identity checks, session revocation, and access containment.'
        printf '%s\n' 'These controls are external: this tool does not perform or independently verify them.'
        printf '%s\n' 'Keep access contained and factor administration serialized until recovery is reconciled.'
        printf '%s\n' 'Failed installation can leave no active factor. No automatic retry or old-factor restoration occurs.'
        printf 'Type exactly: RECOVER %s ON %s REQUEST %s\n' "${account}" "${hostname}" "${RECOVERY_REQUEST_ID}"
    } > /dev/tty
    IFS= read -r -p 'Authorization: ' answer < /dev/tty || return 1
    [[ "${answer}" == "RECOVER ${account} ON ${hostname} REQUEST ${RECOVERY_REQUEST_ID}" ]]
}

recovery_main() {
    local operation='' account='' host='' hostname='' digest mutation=false
    local RECOVERY_APPROVAL='' RECOVERY_SIGNATURE='' RECOVERY_ACCEPTED_SHA='' RECOVERY_REQUEST_ID=''
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --request|--dry-run|--recover)
                [[ -z "${operation}" ]] || return 2
                operation="$1"; shift ;;
            --host|--expected-hostname|--approval|--signature)
                [[ "$#" -ge 2 && -n "$2" ]] || return 2
                case "$1" in
                    --host) [[ -z "${host}" ]] || return 2; host="$2" ;;
                    --expected-hostname) [[ -z "${hostname}" ]] || return 2; hostname="$2" ;;
                    --approval) [[ -z "${RECOVERY_APPROVAL}" ]] || return 2; RECOVERY_APPROVAL="$2" ;;
                    --signature) [[ -z "${RECOVERY_SIGNATURE}" ]] || return 2; RECOVERY_SIGNATURE="$2" ;;
                esac
                shift 2 ;;
            -*) recovery_usage; return 2 ;;
            *) [[ -z "${account}" ]] || return 2; account="$1"; shift ;;
        esac
    done
    [[ -n "${operation}" && -n "${account}" && -n "${host}" && -n "${hostname}" ]] || {
        recovery_usage; return 2;
    }
    rotation_validate "${account}" "${host}" "${hostname}" || return 2
    if [[ "${operation}" == --request ]]; then
        [[ -z "${RECOVERY_APPROVAL}" && -z "${RECOVERY_SIGNATURE}" ]] || return 2
        digest="$(rotation_snapshot "${account}" "${host}" "${hostname}")" || return 1
        python3 "${RECOVERY_DIR}/osmap-totp-recovery-approval.py" --template \
            --account "${account}" --host "${host}" --expected-hostname "${hostname}" --digest "${digest}"
        return "$?"
    fi
    [[ -n "${RECOVERY_APPROVAL}" && -n "${RECOVERY_SIGNATURE}" ]] || {
        recovery_usage; return 2;
    }
    [[ "${operation}" != --recover ]] || mutation=true
    run_factor_replacement "${account}" "${host}" "${hostname}" "${mutation}" RECOVERY
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    recovery_main "$@"
fi
