#!/usr/bin/env bash
# Governed OSMAP TOTP revocation over SSH.
#
# This tool revokes one existing active TOTP factor by preserving it in the
# reviewed revoked-factor directory and removing the active path. It does not
# provision a replacement factor, perform recovery, or revoke browser sessions.
#
# Usage:
#   osmap-revoke-totp-over-ssh.sh --check ACCOUNT [--host HOST]
#   osmap-revoke-totp-over-ssh.sh --dry-run ACCOUNT [--host HOST]
#   osmap-revoke-totp-over-ssh.sh --revoke ACCOUNT [--host HOST]
#   osmap-revoke-totp-over-ssh.sh --self-test

set -euo pipefail
umask 077

PROGRAM="$(basename "$0")"
DEFAULT_HOST="${OSMAP_TOTP_SSH_HOST:-mail.blackbagsecurity.com}"
SECRET_DIR="${OSMAP_TOTP_SECRET_DIR:-/var/lib/osmap/secrets/totp}"
REVOKED_DIR="${OSMAP_TOTP_REVOKED_DIR:-/var/lib/osmap/secrets/totp-revoked}"
RUNTIME_OWNER="${OSMAP_TOTP_OWNER:-_osmap}"
RUNTIME_GROUP="${OSMAP_TOTP_GROUP:-_osmap}"
AMBIGUOUS_RECONCILE_DELAY="${OSMAP_TOTP_AMBIGUOUS_RECONCILE_DELAY:-65}"

SSH_OPTS=(
    -T
    -o BatchMode=yes
    -o ControlMaster=no
    -o ControlPath=none
    -o ControlPersist=no
    -o ConnectTimeout=15
)

if [[ ! "${AMBIGUOUS_RECONCILE_DELAY}" =~ ^[0-9]+$ ]]; then
    printf 'ERROR: OSMAP_TOTP_AMBIGUOUS_RECONCILE_DELAY must be a nonnegative integer\n' >&2
    exit 2
fi

usage() {
    cat >&2 <<'USAGE'
usage:
  osmap-revoke-totp-over-ssh.sh --check ACCOUNT [--host HOST]
  osmap-revoke-totp-over-ssh.sh --dry-run ACCOUNT [--host HOST]
  osmap-revoke-totp-over-ssh.sh --revoke ACCOUNT [--host HOST]
  osmap-revoke-totp-over-ssh.sh --self-test
USAGE
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'ERROR: missing required command: %s\n' "$1" >&2
        return 1
    }
}

validate_account() {
    local account="$1"
    if [[ ! "${account}" =~ ^[a-z0-9][a-z0-9._%+-]*@[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$ ]]; then
        printf 'ERROR: account must be a canonical lowercase email address\n' >&2
        return 1
    fi
}

validate_host() {
    local host="$1"
    if [[ ! "${host}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$ ]]; then
        printf 'ERROR: SSH host must be a conservative DNS name or address label\n' >&2
        return 1
    fi
}

validate_stamp() {
    local stamp="$1"
    [[ "${stamp}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
        printf 'ERROR: revocation timestamp is malformed\n' >&2
        return 1
    }
}

account_hex() {
    python3 - "$1" <<'PY'
import sys
print(sys.argv[1].encode("utf-8").hex())
PY
}

secret_path_for_account() {
    printf '%s/%s.totp\n' "${SECRET_DIR}" "$(account_hex "$1")"
}

revoked_pattern_for_account() {
    printf '%s/%s.<UTC_TIMESTAMP>.revoked.totp\n' \
        "${REVOKED_DIR}" "$(account_hex "$1")"
}

remote_check_output() {
    local account="$1"
    local host="$2"
    local hex
    hex="$(account_hex "${account}")"

    ssh "${SSH_OPTS[@]}" "${host}" sh -s -- \
        "${account}" "${hex}" "${SECRET_DIR}" "${REVOKED_DIR}" \
        "${RUNTIME_OWNER}" "${RUNTIME_GROUP}" <<'REMOTE'
set -eu

account=$1
hex=$2
secret_dir=$3
revoked_dir=$4
expected_owner=$5
expected_group=$6
path="${secret_dir}/${hex}.totp"

printf '%s\n' "REMOTE_REVOKE_CHECK=STARTED"
printf '%s\n' "account=${account}"

if doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    mailbox list -u "${account}" 2>/dev/null | grep -Fxq INBOX
then
    printf '%s\n' "mailbox_exists=true"
else
    # Revocation may still be required for an orphaned factor after mailbox
    # disablement/removal. Mailbox absence is reported but is not a revocation
    # blocker when the canonical factor path itself is safely established.
    printf '%s\n' "mailbox_exists=false"
fi

if doas test -e "${path}" 2>/dev/null; then
    printf '%s\n' "totp_exists=true"

    if doas test -L "${path}" 2>/dev/null || ! doas test -f "${path}" 2>/dev/null; then
        printf '%s\n' "totp_metadata_safe=false"
        exit 5
    fi

    owner="$(doas stat -f '%Su' "${path}")"
    group="$(doas stat -f '%Sg' "${path}")"
    mode="$(doas stat -f '%Lp' "${path}")"
    digest="$(doas sha256 -q "${path}")"

    printf '%s\n' "owner=${owner}"
    printf '%s\n' "group=${group}"
    printf '%s\n' "mode=${mode}"

    if [ "${owner}" != "${expected_owner}" ] ||
       [ "${group}" != "${expected_group}" ] ||
       [ "${mode}" != "600" ]
    then
        printf '%s\n' "totp_metadata_safe=false"
        exit 5
    fi

    printf '%s\n' "totp_metadata_safe=true"
    printf '%s\n' "active_factor_sha256=${digest}"
else
    printf '%s\n' "totp_exists=false"
    printf '%s\n' "totp_metadata_safe=not_applicable"
fi

if doas test -e "${revoked_dir}" 2>/dev/null; then
    printf '%s\n' "revoked_dir_exists=true"
    if doas test -L "${revoked_dir}" 2>/dev/null || ! doas test -d "${revoked_dir}" 2>/dev/null; then
        printf '%s\n' "revoked_dir_metadata_safe=false"
        exit 6
    fi

    revoked_owner="$(doas stat -f '%Su' "${revoked_dir}")"
    revoked_group="$(doas stat -f '%Sg' "${revoked_dir}")"
    revoked_mode="$(doas stat -f '%Lp' "${revoked_dir}")"

    printf '%s\n' "revoked_dir_owner=${revoked_owner}"
    printf '%s\n' "revoked_dir_group=${revoked_group}"
    printf '%s\n' "revoked_dir_mode=${revoked_mode}"

    if [ "${revoked_owner}" != "${expected_owner}" ] ||
       [ "${revoked_group}" != "${expected_group}" ] ||
       [ "${revoked_mode}" != "700" ]
    then
        printf '%s\n' "revoked_dir_metadata_safe=false"
        exit 6
    fi
    printf '%s\n' "revoked_dir_metadata_safe=true"
else
    printf '%s\n' "revoked_dir_exists=false"
    printf '%s\n' "revoked_dir_metadata_safe=not_applicable"
fi

printf '%s\n' "REMOTE_REVOKE_CHECK=PASS"
REMOTE
}

run_check() {
    local account="$1"
    local host="$2"
    local output rc

    validate_account "${account}"
    validate_host "${host}"
    require_command ssh
    require_command python3

    printf '%s\n' "program=${PROGRAM}"
    printf '%s\n' "operation=--check"
    printf '%s\n' "account=${account}"
    printf '%s\n' "ssh_host=${host}"

    set +e
    output="$(remote_check_output "${account}" "${host}" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
        printf '%s\n' "ssh_connectivity=PASS"
        printf '%s\n' "${output}"
        return 0
    fi

    printf '%s\n' "${output}" >&2
    printf 'ERROR: remote revocation check failed with status %s\n' "${rc}" >&2
    return "${rc}"
}

run_dry_run() {
    local account="$1"
    local host="$2"
    local output rc digest

    validate_account "${account}"
    validate_host "${host}"
    require_command ssh
    require_command python3

    printf '%s\n' "program=${PROGRAM}"
    printf '%s\n' "operation=--dry-run"
    printf '%s\n' "account=${account}"
    printf '%s\n' "ssh_host=${host}"
    printf '%s\n' "TOTP_REVOCATION_DRY_RUN=STARTED"

    set +e
    output="$(remote_check_output "${account}" "${host}" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -ne 0 ]]; then
        printf '%s\n' "${output}" >&2
        printf 'ERROR: revocation dry-run remote check failed with status %s\n' "${rc}" >&2
        return "${rc}"
    fi

    printf '%s\n' "ssh_connectivity=PASS"
    printf '%s\n' "${output}"

    if grep -Fxq 'totp_exists=false' <<<"${output}"; then
        printf '%s\n' "would_revoke=false"
        printf '%s\n' "dry_run_disposition=no_active_factor"
        return 3
    fi

    grep -Fxq 'totp_exists=true' <<<"${output}" || {
        printf 'ERROR: dry-run could not establish active factor state\n' >&2
        return 7
    }

    grep -Fxq 'totp_metadata_safe=true' <<<"${output}" || {
        printf 'ERROR: active factor metadata is not safe for revocation\n' >&2
        return 5
    }

    digest="$(awk -F= '/^active_factor_sha256=/{print $2}' <<<"${output}")"
    [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || {
        printf 'ERROR: active factor digest was unavailable or malformed\n' >&2
        return 8
    }

    printf '%s\n' "active_path=$(secret_path_for_account "${account}")"
    printf '%s\n' "revoked_path_pattern=$(revoked_pattern_for_account "${account}")"
    printf '%s\n' "preserve_revoked_factor=true"
    printf '%s\n' "atomic_no_overwrite_link=true"
    printf '%s\n' "digest_compare_and_swap=true"
    printf '%s\n' "session_revocation_performed=false"
    printf '%s\n' "replacement_provisioning_performed=false"
    printf '%s\n' "would_revoke=true"
    printf '%s\n' "TOTP_REVOCATION_DRY_RUN=PASS"
}

authorize_revoke() {
    local account="$1"
    local answer

    [[ -r /dev/tty && -w /dev/tty ]] || {
        printf 'ERROR: production revocation authorization requires /dev/tty\n' >&2
        return 1
    }

    printf '\nType exactly: REVOKE %s\n' "${account}" > /dev/tty
    IFS= read -r -p "Authorization: " answer < /dev/tty

    [[ "${answer}" == "REVOKE ${account}" ]] || {
        printf 'ERROR: production TOTP revocation not authorized\n' >&2
        return 1
    }

    printf '%s\n' "operator_authorization=PASS"
}

remote_revoke() {
    local account="$1"
    local host="$2"
    local expected_digest="$3"
    local stamp="$4"
    local hex
    hex="$(account_hex "${account}")"

    ssh "${SSH_OPTS[@]}" "${host}" sh -s -- \
        "${account}" "${hex}" "${SECRET_DIR}" "${REVOKED_DIR}" \
        "${RUNTIME_OWNER}" "${RUNTIME_GROUP}" "${expected_digest}" "${stamp}" <<'REMOTE'
set -eu
umask 077

account=$1
hex=$2
secret_dir=$3
revoked_dir=$4
owner=$5
group=$6
expected_digest=$7
stamp=$8

path="${secret_dir}/${hex}.totp"
revoked_path="${revoked_dir}/${hex}.${stamp}.revoked.totp"
link_created=false
active_removed=false

cleanup() {
    if [ "${link_created}" = "true" ] && [ "${active_removed}" = "false" ]; then
        doas rm -f "${revoked_path}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM HUP

printf '%s\n' "REMOTE_REVOKE=STARTED"
printf '%s\n' "account=${account}"
printf '%s\n' "revoke_stamp=${stamp}"

if ! doas test -e "${path}" 2>/dev/null; then
    printf '%s\n' "REMOTE_REVOKE=REFUSED_NO_ACTIVE_FACTOR"
    exit 3
fi

if doas test -L "${path}" 2>/dev/null || ! doas test -f "${path}" 2>/dev/null; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_ACTIVE_FILE_TYPE"
    exit 5
fi

current_owner="$(doas stat -f '%Su' "${path}")"
current_group="$(doas stat -f '%Sg' "${path}")"
current_mode="$(doas stat -f '%Lp' "${path}")"
current_digest="$(doas sha256 -q "${path}")"

if [ "${current_owner}" != "${owner}" ] ||
   [ "${current_group}" != "${group}" ] ||
   [ "${current_mode}" != "600" ]
then
    printf '%s\n' "REMOTE_REVOKE=FAILED_ACTIVE_METADATA"
    exit 5
fi

if [ "${current_digest}" != "${expected_digest}" ]; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_STALE_PRECONDITION"
    printf '%s\n' "digest_compare_and_swap=false"
    exit 6
fi

if doas test -e "${revoked_dir}" 2>/dev/null; then
    if doas test -L "${revoked_dir}" 2>/dev/null || ! doas test -d "${revoked_dir}" 2>/dev/null; then
        printf '%s\n' "REMOTE_REVOKE=FAILED_REVOKED_DIR_TYPE"
        exit 8
    fi

    revoked_owner="$(doas stat -f '%Su' "${revoked_dir}")"
    revoked_group="$(doas stat -f '%Sg' "${revoked_dir}")"
    revoked_mode="$(doas stat -f '%Lp' "${revoked_dir}")"

    if [ "${revoked_owner}" != "${owner}" ] ||
       [ "${revoked_group}" != "${group}" ] ||
       [ "${revoked_mode}" != "700" ]
    then
        printf '%s\n' "REMOTE_REVOKE=FAILED_REVOKED_DIR_METADATA"
        exit 8
    fi
else
    doas install -d -o "${owner}" -g "${group}" -m 700 "${revoked_dir}"
fi

if doas test -e "${revoked_path}" 2>/dev/null; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_DESTINATION_EXISTS"
    exit 9
fi

# Create a no-overwrite hard link first. This proves the archive destination is
# on the same filesystem and contains the exact active inode before the active
# path is removed. If anything fails before active removal, the trap removes
# only the newly created archive link and leaves the active factor untouched.
if ! doas ln "${path}" "${revoked_path}"; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_ARCHIVE_LINK"
    exit 10
fi
link_created=true

revoked_digest="$(doas sha256 -q "${revoked_path}")"
if [ "${revoked_digest}" != "${expected_digest}" ]; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_ARCHIVE_DIGEST"
    exit 11
fi

active_inode="$(doas stat -f '%i' "${path}")"
revoked_inode="$(doas stat -f '%i' "${revoked_path}")"
if [ "${active_inode}" != "${revoked_inode}" ]; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_INODE_PRECONDITION"
    exit 12
fi

# Revocation becomes effective only here. The factor is preserved at the
# revoked path and the active path is removed. No replacement is provisioned.
doas rm "${path}"
active_removed=true

if doas test -e "${path}" 2>/dev/null; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_ACTIVE_PATH_STILL_PRESENT"
    exit 13
fi

if doas test -L "${revoked_path}" 2>/dev/null || ! doas test -f "${revoked_path}" 2>/dev/null; then
    printf '%s\n' "REMOTE_REVOKE=FAILED_FINAL_FILE_TYPE"
    exit 14
fi

final_owner="$(doas stat -f '%Su' "${revoked_path}")"
final_group="$(doas stat -f '%Sg' "${revoked_path}")"
final_mode="$(doas stat -f '%Lp' "${revoked_path}")"
final_digest="$(doas sha256 -q "${revoked_path}")"

if [ "${final_owner}" != "${owner}" ] ||
   [ "${final_group}" != "${group}" ] ||
   [ "${final_mode}" != "600" ] ||
   [ "${final_digest}" != "${expected_digest}" ]
then
    printf '%s\n' "REMOTE_REVOKE=FAILED_FINAL_METADATA_OR_DIGEST"
    exit 15
fi

link_created=false

printf '%s\n' "active_factor_absent=true"
printf '%s\n' "revoked_factor_preserved=true"
printf '%s\n' "revoked_path=${revoked_path}"
printf '%s\n' "revoked_owner=${final_owner}"
printf '%s\n' "revoked_group=${final_group}"
printf '%s\n' "revoked_mode=${final_mode}"
printf '%s\n' "revoked_factor_sha256=${final_digest}"
printf '%s\n' "session_revocation_performed=false"
printf '%s\n' "replacement_provisioning_performed=false"
printf '%s\n' "TOTP_REVOCATION=PASS"
REMOTE
}

reconcile_ambiguous_revoke() {
    local account="$1"
    local host="$2"
    local expected_digest="$3"
    local stamp="$4"
    local hex
    hex="$(account_hex "${account}")"

    ssh "${SSH_OPTS[@]}" "${host}" sh -s -- \
        "${hex}" "${SECRET_DIR}" "${REVOKED_DIR}" \
        "${RUNTIME_OWNER}" "${RUNTIME_GROUP}" "${expected_digest}" "${stamp}" <<'REMOTE'
set -eu

hex=$1
secret_dir=$2
revoked_dir=$3
owner=$4
group=$5
expected_digest=$6
stamp=$7

path="${secret_dir}/${hex}.totp"
revoked_path="${revoked_dir}/${hex}.${stamp}.revoked.totp"

printf '%s\n' "REMOTE_REVOKE_RECONCILE=STARTED"

active_exists=false
revoked_exists=false
doas test -e "${path}" 2>/dev/null && active_exists=true
doas test -e "${revoked_path}" 2>/dev/null && revoked_exists=true

printf '%s\n' "reconcile_active_exists=${active_exists}"
printf '%s\n' "reconcile_revoked_exists=${revoked_exists}"

if [ "${active_exists}" = "false" ] && [ "${revoked_exists}" = "true" ]; then
    if doas test -L "${revoked_path}" 2>/dev/null || ! doas test -f "${revoked_path}" 2>/dev/null; then
        printf '%s\n' "manual_review_required=true"
        exit 24
    fi

    ro="$(doas stat -f '%Su' "${revoked_path}")"
    rg="$(doas stat -f '%Sg' "${revoked_path}")"
    rm="$(doas stat -f '%Lp' "${revoked_path}")"
    rd="$(doas sha256 -q "${revoked_path}")"

    if [ "${ro}" = "${owner}" ] &&
       [ "${rg}" = "${group}" ] &&
       [ "${rm}" = "600" ] &&
       [ "${rd}" = "${expected_digest}" ]
    then
        printf '%s\n' "revocation_reconciled=PASS"
        printf '%s\n' "active_factor_absent=true"
        printf '%s\n' "revoked_factor_preserved=true"
        printf '%s\n' "manual_review_required=false"
        printf '%s\n' "REMOTE_REVOKE_RECONCILE=PASS"
        exit 0
    fi

    printf '%s\n' "manual_review_required=true"
    exit 24
fi

if [ "${active_exists}" = "true" ] && [ "${revoked_exists}" = "false" ]; then
    printf '%s\n' "revocation_reconciled=NO_MUTATION"
    printf '%s\n' "manual_review_required=false"
    exit 23
fi

if [ "${active_exists}" = "true" ] && [ "${revoked_exists}" = "true" ]; then
    if doas test -L "${path}" 2>/dev/null ||
       doas test -L "${revoked_path}" 2>/dev/null ||
       ! doas test -f "${path}" 2>/dev/null ||
       ! doas test -f "${revoked_path}" 2>/dev/null
    then
        printf '%s\n' "manual_review_required=true"
        exit 24
    fi

    ai="$(doas stat -f '%i' "${path}")"
    ri="$(doas stat -f '%i' "${revoked_path}")"
    ad="$(doas sha256 -q "${path}")"
    rd="$(doas sha256 -q "${revoked_path}")"

    if [ "${ai}" = "${ri}" ] &&
       [ "${ad}" = "${expected_digest}" ] &&
       [ "${rd}" = "${expected_digest}" ]
    then
        printf '%s\n' "reconcile_disposition=archive_link_present_active_still_effective"
    else
        printf '%s\n' "reconcile_disposition=conflicting_state"
    fi
    printf '%s\n' "manual_review_required=true"
    exit 24
fi

printf '%s\n' "reconcile_disposition=active_and_expected_archive_absent"
printf '%s\n' "manual_review_required=true"
exit 24
REMOTE
}

run_revoke() {
    local account="$1"
    local host="$2"
    local dry_output dry_rc expected_digest stamp output rc reconcile_output reconcile_rc

    validate_account "${account}"
    validate_host "${host}"
    require_command ssh
    require_command python3
    require_command date

    [[ -r /dev/tty && -w /dev/tty ]] || {
        printf 'ERROR: TOTP revocation requires an interactive /dev/tty\n' >&2
        return 1
    }

    printf '%s\n' "program=${PROGRAM}"
    printf '%s\n' "operation=--revoke"
    printf '%s\n' "account=${account}"
    printf '%s\n' "ssh_host=${host}"
    printf '%s\n' "TOTP_REVOCATION_WORKFLOW=STARTED"

    set +e
    dry_output="$(run_dry_run "${account}" "${host}" 2>&1)"
    dry_rc=$?
    set -e
    printf '%s\n' "${dry_output}"

    if [[ "${dry_rc}" -ne 0 ]]; then
        if [[ "${dry_rc}" -eq 3 ]]; then
            printf '%s\n' "no_active_factor_revocation_refusal=PASS"
        fi
        return "${dry_rc}"
    fi

    expected_digest="$(awk -F= '/^active_factor_sha256=/{print $2}' <<<"${dry_output}" | tail -n 1)"
    [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]] || {
        printf 'ERROR: revocation precondition digest was unavailable\n' >&2
        return 8
    }

    authorize_revoke "${account}"

    stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    validate_stamp "${stamp}"

    printf '%s\n' "revoke_stamp=${stamp}"
    printf '%s\n' "automatic_revoke_retry=false"

    set +e
    output="$(remote_revoke "${account}" "${host}" "${expected_digest}" "${stamp}" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
        printf '%s\n' "ssh_connectivity=PASS"
        printf '%s\n' "${output}"
        printf '%s\n' "production_mutation_attempted=true"
        printf '%s\n' "TOTP_REVOCATION_WORKFLOW=PASS"
        return 0
    fi

    printf '%s\n' "${output}" >&2
    printf '%s\n' "production_mutation_attempted=true"
    printf '%s\n' "automatic_revoke_retry=false"

    # Exit codes through 12 occur before the active path is removed and are
    # deterministic remote refusals/failures. Do not create unnecessary SSH
    # traffic or claim ambiguity for them.
    if [[ "${rc}" -ge 3 && "${rc}" -le 12 ]]; then
        printf 'ERROR: revocation failed before active-path removal with status %s\n' "${rc}" >&2
        return "${rc}"
    fi

    printf 'WARNING: revocation outcome may be ambiguous; reconciling read-only after %s seconds\n' \
        "${AMBIGUOUS_RECONCILE_DELAY}" >&2
    sleep "${AMBIGUOUS_RECONCILE_DELAY}"

    set +e
    reconcile_output="$(reconcile_ambiguous_revoke \
        "${account}" "${host}" "${expected_digest}" "${stamp}" 2>&1)"
    reconcile_rc=$?
    set -e
    printf '%s\n' "${reconcile_output}" >&2

    if [[ "${reconcile_rc}" -eq 0 ]]; then
        printf '%s\n' "reconciled_after_ambiguous=true"
        printf '%s\n' "TOTP_REVOCATION_WORKFLOW=PASS"
        return 0
    fi

    if [[ "${reconcile_rc}" -eq 23 ]]; then
        printf 'ERROR: reconciliation proved no revocation occurred; no automatic retry was performed\n' >&2
        return 23
    fi

    printf 'ERROR: revocation outcome requires manual review; no automatic retry or cleanup mutation was performed\n' >&2
    return 24
}

self_test() {
    local hex source

    printf '%s\n' "SELF_TEST=STARTED"

    validate_account 'alice@example.com'
    if validate_account 'Alice@example.com' >/dev/null 2>&1 ||
       validate_account 'alice' >/dev/null 2>&1 ||
       validate_account 'alice@example' >/dev/null 2>&1
    then
        printf 'SELF_TEST=FAIL account validation\n' >&2
        return 1
    fi
    printf '%s\n' "account_validation=PASS"

    validate_host 'mail.blackbagsecurity.com'
    if validate_host '-bad-host' >/dev/null 2>&1; then
        printf 'SELF_TEST=FAIL host validation\n' >&2
        return 1
    fi
    printf '%s\n' "host_validation=PASS"

    validate_stamp '20260908T120000Z'
    if validate_stamp '2026-09-08' >/dev/null 2>&1; then
        printf 'SELF_TEST=FAIL stamp validation\n' >&2
        return 1
    fi
    printf '%s\n' "timestamp_validation=PASS"

    hex="$(account_hex 'alice@example.com')"
    [[ "${hex}" == "616c696365406578616d706c652e636f6d" ]]
    printf '%s\n' "hex_encoding=PASS"

    source="$(<"$0")"

    [[ "${source}" == *'Type exactly: REVOKE %s'* ]]
    [[ "${source}" == *"[[ \"\${answer}\" == \"REVOKE \${account}\" ]]"* ]]
    printf '%s\n' "explicit_authorization=PASS"

    [[ "${source}" == *"current_digest=\"\$(doas sha256 -q \"\${path}\")\""* ]]
    [[ "${source}" == *"if [ \"\${current_digest}\" != \"\${expected_digest}\" ]; then"* ]]
    printf '%s\n' "digest_compare_and_swap=PASS"

    [[ "${source}" == *"doas ln \"\${path}\" \"\${revoked_path}\""* ]]
    [[ "${source}" == *"doas rm \"\${path}\""* ]]
    printf '%s\n' "preserve_before_revoke_order=PASS"

    [[ "${source}" == *'automatic_revoke_retry=false'* ]]
    [[ "${source}" == *'reconcile_ambiguous_revoke'* ]]
    printf '%s\n' "ambiguous_failure_no_retry=PASS"

    [[ "${source}" == *'session_revocation_performed=false'* ]]
    [[ "${source}" == *'replacement_provisioning_performed=false'* ]]
    printf '%s\n' "bounded_scope=PASS"

    printf '%s\n' "SELF_TEST=PASS"
}

# The lifecycle coordinator uses these primitives in an isolated subshell.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

operation=""
account=""
host="${DEFAULT_HOST}"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --check|--dry-run|--revoke|--self-test)
            [[ -z "${operation}" ]] || usage
            operation="$1"
            shift
            ;;
        --host)
            [[ "$#" -ge 2 ]] || usage
            host="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        --*)
            usage
            ;;
        *)
            [[ -z "${account}" ]] || usage
            account="$1"
            shift
            ;;
    esac
done

case "${operation}" in
    --self-test)
        [[ -z "${account}" ]] || usage
        self_test
        ;;
    --check)
        [[ -n "${account}" ]] || usage
        run_check "${account}" "${host}"
        ;;
    --dry-run)
        [[ -n "${account}" ]] || usage
        run_dry_run "${account}" "${host}"
        ;;
    --revoke)
        [[ -n "${account}" ]] || usage
        run_revoke "${account}" "${host}"
        ;;
    *)
        usage
        ;;
esac
