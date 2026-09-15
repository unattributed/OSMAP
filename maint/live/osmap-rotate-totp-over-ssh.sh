#!/usr/bin/env bash
# Governed rotation: verify enrollment, preserve/revoke, install without overwrite.
# Never retry a mutation or restore an old factor after an uncertain outcome.
set -euo pipefail
umask 077

LIFECYCLE_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=maint/live/osmap-provision-totp-over-ssh.sh
source "${LIFECYCLE_DIR}/osmap-provision-totp-over-ssh.sh"
SSH_OPTS+=(-o StrictHostKeyChecking=yes)

rotation_usage() {
    printf '%s\n' 'usage: osmap-rotate-totp-over-ssh.sh --dry-run|--rotate ACCOUNT --host HOST --expected-hostname FQDN' >&2
    return 2
}

rotation_validate() {
    validate_account "$1" && validate_host "$2" && validate_host "$3" || return 2
    # Existing primitives pass these values through the remote shell. Constrain
    # them before making any SSH call, including sourced environment overrides.
    local directory identity
    for directory in "${SECRET_DIR}" "${REVOKED_DIR}"; do
        [[ "${directory}" =~ ^/[A-Za-z0-9_/-]+$ &&
           "${directory}" != / && "${directory}" != */ &&
           "${directory}" != *//* ]] || return 2
    done
    [[ "${SECRET_DIR}" != "${REVOKED_DIR}" ]] || return 2
    for identity in "${RUNTIME_OWNER}" "${RUNTIME_GROUP}"; do
        [[ "${identity}" =~ ^[a-z_][a-z0-9_-]*$ ]] || return 2
    done
}

rotation_host_check() {
    local actual
    actual="$(ssh "${SSH_OPTS[@]}" "$1" hostname)" || return 1
    [[ "${actual}" == "$2" ]] || {
        printf '%s\n' 'ERROR: remote hostname does not match --expected-hostname' >&2
        return 1
    }
}

rotation_preflight() (
    # Isolate the revocation helper's function names and process state.
    # shellcheck source=maint/live/osmap-revoke-totp-over-ssh.sh
    source "${LIFECYCLE_DIR}/osmap-revoke-totp-over-ssh.sh"
    SSH_OPTS+=(-o StrictHostKeyChecking=yes)
    # Refuse symlinked or group/world-writable store ancestry. These paths are
    # passed only after rotation_validate has excluded remote shell syntax.
    ssh "${SSH_OPTS[@]}" "$2" sh -s -- "${SECRET_DIR}" "${REVOKED_DIR}" "${RUNTIME_OWNER}" <<'REMOTE'
set -eu
secret_dir=$1
revoked_dir=$2
owner=$3
doas -n test -d "${secret_dir}"
for directory in "${secret_dir}" "${revoked_dir}"; do
    cursor=${directory}
    while [ "${cursor}" != / ]; do
        if doas -n test -L "${cursor}"; then exit 8; fi
        if doas -n test -e "${cursor}"; then
            doas -n test -d "${cursor}"
            directory_owner=$(doas -n stat -f '%Su' "${cursor}")
            directory_mode=$(doas -n stat -f '%Lp' "${cursor}")
            case "${directory_mode}" in ''|*[!0-7]*) exit 8 ;; esac
            [ "${directory_owner}" = root ] || [ "${directory_owner}" = "${owner}" ]
            [ "$((0${directory_mode} & 0022))" -eq 0 ]
        else
            # Only the archive directory itself may be absent.
            [ "${cursor}" = "${revoked_dir}" ]
        fi
        cursor=$(dirname "${cursor}")
    done
done
REMOTE
    guard_rc=$?
    [[ "${guard_rc}" -eq 0 ]] || return "${guard_rc}"
    run_dry_run "$1" "$2"
)

rotation_revoke() (
    # shellcheck source=maint/live/osmap-revoke-totp-over-ssh.sh
    source "${LIFECYCLE_DIR}/osmap-revoke-totp-over-ssh.sh"
    SSH_OPTS+=(-o StrictHostKeyChecking=yes)
    remote_revoke "$1" "$2" "$3" "$4"
)

rotation_snapshot() {
    local account="$1" host="$2" expected_hostname="$3" output
    rotation_validate "${account}" "${host}" "${expected_hostname}" || return 2
    rotation_host_check "${host}" "${expected_hostname}" || return 1
    output="$(rotation_preflight "${account}" "${host}")" || return 1
    # Rotation requires an existing mailbox AND a safely identified factor.
    grep -Fxq 'mailbox_exists=true' <<<"${output}" || return 1
    grep -Fxq 'totp_exists=true' <<<"${output}" || return 1
    grep -Fxq 'totp_metadata_safe=true' <<<"${output}" || return 1
    grep -Fxq 'TOTP_REVOCATION_DRY_RUN=PASS' <<<"${output}" || return 1
    local digest
    digest="$(awk -F= '/^active_factor_sha256=/{print $2}' <<<"${output}")"
    [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "${digest}"
}

rotation_authorize() {
    local account="$1" host="$2" expected_hostname="$3" answer
    [[ -r /dev/tty && -w /dev/tty ]] || return 1
    {
        printf '\nPlanned factor rotation for %s on %s (%s).\n' "${account}" "${host}" "${expected_hostname}"
        printf '%s\n' 'The old factor will be preserved but will not be restored automatically.'
        printf '%s\n' 'A failed install can leave the account without an active factor.'
        printf '%s\n' 'Existing browser sessions remain valid; replay counters are preserved.'
        printf '%s\n' 'Serialize all factor administration for this account, including legacy tools.'
        printf 'Type exactly: ROTATE %s ON %s\n' "${account}" "${expected_hostname}"
    } > /dev/tty
    IFS= read -r -p 'Authorization: ' answer < /dev/tty || return 1
    [[ "${answer}" == "ROTATE ${account} ON ${expected_hostname}" ]]
}

rotation_pending() {
    printf '%s\n' "TOTP_${1:-ROTATION}=INCOMPLETE" 'manual_review_required=true' \
        'automatic_mutation_retry=false' 'old_factor_restore_performed=false' >&2
    return 24
}

run_factor_replacement() {
    local account="$1" host="$2" expected_hostname="$3" mutation="$4"
    local workflow="$5"
    local old_digest new_digest final_digest stamp output secret
    [[ "${workflow}" == ROTATION || "${workflow}" == RECOVERY || "${workflow}" == RECOVERY_REHEARSAL ]] || return 2
    rotation_validate "${account}" "${host}" "${expected_hostname}" || return 2
    require_command ssh || return 1
    require_command python3 || return 1
    require_command sha256sum || return 1
    old_digest="$(rotation_snapshot "${account}" "${host}" "${expected_hostname}")" || return 1
    if [[ "${workflow}" != ROTATION ]]; then
        recovery_approve_snapshot "${account}" "${host}" "${expected_hostname}" "${old_digest}" || return 1
    fi
    printf '%s\n' "account=${account}" "ssh_host=${host}" "expected_hostname=${expected_hostname}" \
        "previous_factor_sha256=${old_digest}" 'session_revocation_performed=false' \
        'replay_counter_reset=false' 'automatic_mutation_retry=false'
    if [[ "${mutation}" == false ]]; then
        if [[ "${workflow}" == ROTATION ]]; then
            printf '%s\n' 'would_rotate=true'
        else
            printf '%s\n' 'would_recover=true'
        fi
        printf '%s\n' 'preinstall_enrollment_verification=true' \
            'preserve_before_revoke=true' 'replacement_no_overwrite=true' \
            'whole_rotation_atomic=false' "TOTP_${workflow}_DRY_RUN=PASS"
        return 0
    fi

    # Complete enrollment while the original factor is still effective.
    require_command qrencode || return 1
    prepare_enrollment_material "${account}" || return 1
    show_and_verify_enrollment "${account}" || return 1
    if [[ "${workflow}" != ROTATION ]]; then
        recovery_authorize "${account}" "${host}" "${expected_hostname}" || return 1
    else
        rotation_authorize "${account}" "${host}" "${expected_hostname}" || return 1
    fi
    secret="$(<"${SECRET_FILE}")"
    printf '# %s\nsecret=%s\n' "${account}" "${secret}" > "${WORK_ROOT}/candidate.totp" || return 1
    unset secret
    new_digest="$(sha256sum "${WORK_ROOT}/candidate.totp" | awk '{print $1}')"
    [[ "${new_digest}" =~ ^[0-9a-f]{64}$ && "${new_digest}" != "${old_digest}" ]] || return 1
    # Recheck host, mailbox, and exact old factor after operator interaction.
    final_digest="$(rotation_snapshot "${account}" "${host}" "${expected_hostname}")" || return 1
    [[ "${final_digest}" == "${old_digest}" ]] || {
        printf '%s\n' 'ERROR: factor changed during enrollment; no mutation attempted' >&2
        return 1
    }
    if [[ "${workflow}" != ROTATION ]]; then
        recovery_approve_snapshot "${account}" "${host}" "${expected_hostname}" "${old_digest}" || return 1
    fi
    stamp="$(date -u '+%Y%m%dT%H%M%SZ')" || return 1
    printf '%s\n' "revoke_stamp=${stamp}" "replacement_factor_sha256=${new_digest}"

    # A lost response is not permission to proceed. Retain the archive and
    # require read-only reconciliation before any fresh operator decision.
    if ! output="$(rotation_revoke "${account}" "${host}" "${old_digest}" "${stamp}")"; then
        rotation_pending "${workflow}"
        return 24
    fi
    if ! grep -Fxq 'TOTP_REVOCATION=PASS' <<<"${output}" ||
       ! grep -Fxq 'active_factor_absent=true' <<<"${output}" ||
       ! grep -Fxq 'revoked_factor_preserved=true' <<<"${output}" ||
       ! grep -Fxq "revoked_factor_sha256=${old_digest}" <<<"${output}"; then
        rotation_pending "${workflow}"
        return 24
    fi
    printf '%s\n' 'previous_factor_revoked_and_preserved=true'
    # Do not use run_provision: its ambiguity handling may mutate. Here every
    # unsuccessful install stops with the previous factor preserved.
    if ! output="$(remote_provision "${account}" "${host}" "${WORK_ROOT}/candidate.totp" "${new_digest}")"; then
        rotation_pending "${workflow}"
        return 24
    fi
    if ! grep -Fxq 'TOTP_PROVISIONING=PASS' <<<"${output}"; then
        rotation_pending "${workflow}"
        return 24
    fi
    final_digest="$(rotation_snapshot "${account}" "${host}" "${expected_hostname}")" || {
        rotation_pending "${workflow}"
        return 24
    }
    [[ "${final_digest}" == "${new_digest}" ]] || {
        rotation_pending "${workflow}"
        return 24
    }
    printf '%s\n' 'replacement_factor_verified=true' "TOTP_${workflow}=PASS"
}

run_rotation() {
    run_factor_replacement "$@" ROTATION
}

rotation_main() {
    local operation='' account='' host='' expected_hostname=''
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --dry-run|--rotate)
                [[ -z "${operation}" ]] || { rotation_usage; return 2; }
                operation="$1"; shift ;;
            --host|--expected-hostname)
                [[ "$#" -ge 2 ]] || { rotation_usage; return 2; }
                if [[ "$1" == --host ]]; then
                    [[ -z "${host}" ]] || return 2
                    host="$2"
                else
                    [[ -z "${expected_hostname}" ]] || return 2
                    expected_hostname="$2"
                fi
                shift 2 ;;
            -*) rotation_usage; return 2 ;;
            *)
                [[ -z "${account}" ]] || return 2
                account="$1"; shift ;;
        esac
    done
    [[ -n "${operation}" && -n "${account}" && -n "${host}" && -n "${expected_hostname}" ]] || {
        rotation_usage; return 2;
    }
    local mutation=false
    [[ "${operation}" != --rotate ]] || mutation=true
    run_rotation "${account}" "${host}" "${expected_hostname}" "${mutation}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    rotation_main "$@"
fi
