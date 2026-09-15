#!/usr/bin/env bash
# Governed interim OSMAP TOTP operator provisioning over SSH.
#
# This is deliberately narrow operator tooling, not a general account-management
# or factor-rotation interface. It never overwrites an existing active factor.
#
# Usage:
#   osmap-provision-totp-over-ssh.sh --check ACCOUNT [--host HOST]
#   osmap-provision-totp-over-ssh.sh --dry-run ACCOUNT [--host HOST]
#   osmap-provision-totp-over-ssh.sh --provision ACCOUNT [--host HOST]
#   osmap-provision-totp-over-ssh.sh --self-test
#
# Sensitive enrollment material is shown only on /dev/tty and is not emitted on
# standard output/stderr. Do not redirect /dev/tty during enrollment.

set -euo pipefail
umask 077

PROGRAM="$(basename "$0")"
DEFAULT_HOST="${OSMAP_TOTP_SSH_HOST:-mail.blackbagsecurity.com}"
SECRET_DIR="${OSMAP_TOTP_SECRET_DIR:-/var/lib/osmap/secrets/totp}"
REVOKED_DIR="${OSMAP_TOTP_REVOKED_DIR:-/var/lib/osmap/secrets/totp-revoked}"
RUNTIME_OWNER="${OSMAP_TOTP_OWNER:-_osmap}"
RUNTIME_GROUP="${OSMAP_TOTP_GROUP:-_osmap}"
ISSUER="${OSMAP_TOTP_ISSUER:-OSMAP}"
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

WORK_ROOT=""
SECRET_FILE=""
URI_FILE=""

usage() {
    cat >&2 <<'USAGE'
usage:
  osmap-provision-totp-over-ssh.sh --check ACCOUNT [--host HOST]
  osmap-provision-totp-over-ssh.sh --dry-run ACCOUNT [--host HOST]
  osmap-provision-totp-over-ssh.sh --provision ACCOUNT [--host HOST]
  osmap-provision-totp-over-ssh.sh --self-test
USAGE
    exit 2
}

cleanup_local() {
    if [[ -n "${WORK_ROOT}" && -d "${WORK_ROOT}" ]]; then
        rm -rf -- "${WORK_ROOT}"
    fi
}

on_interrupt() {
    cleanup_local
    trap - EXIT INT TERM HUP
    exit 130
}

trap cleanup_local EXIT
trap on_interrupt INT TERM HUP

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
    return 0
}

validate_host() {
    local host="$1"
    if [[ ! "${host}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$ ]]; then
        printf 'ERROR: SSH host must be a conservative DNS name or address label\n' >&2
        return 1
    fi
    return 0
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

generate_secret() {
    python3 <<'PY'
import base64
import os
print(base64.b32encode(os.urandom(20)).decode("ascii").rstrip("="))
PY
}

build_otpauth_uri() {
    python3 - "$1" "${ISSUER}" 3<<<"$2" <<'PY'
import sys
import urllib.parse

account, issuer = sys.argv[1:3]
with open(3) as channel:
    secret = channel.read().strip()
label = urllib.parse.quote(f"{issuer}:{account}", safe="")
query = urllib.parse.urlencode({
    "secret": secret,
    "issuer": issuer,
    "algorithm": "SHA1",
    "digits": "6",
    "period": "30",
})
print(f"otpauth://totp/{label}?{query}")
PY
}

totp_code() {
    local secret="$1"
    local epoch="${2:-$(date +%s)}"
    local digits="${3:-6}"
    python3 - "${epoch}" "${digits}" 3<<<"${secret}" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys

with open(3) as channel:
    secret = channel.read().strip().upper()
epoch = int(sys.argv[1])
digits = int(sys.argv[2])
pad = "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret + pad, casefold=True)
counter = epoch // 30
msg = struct.pack(">Q", counter)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
print(str(value % (10 ** digits)).zfill(digits))
PY
}

verify_totp_code() {
    local secret="$1"
    local code="$2"
    local epoch="${3:-$(date +%s)}"
    python3 - "${epoch}" 3<<<"${secret}" 4<<<"${code}" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys

with open(3) as channel:
    secret = channel.read().strip().upper()
with open(4) as channel:
    code = channel.read().strip()
epoch = int(sys.argv[1])

if len(code) != 6 or not code.isdigit():
    raise SystemExit(1)

pad = "=" * ((8 - len(secret) % 8) % 8)
try:
    key = base64.b32decode(secret + pad, casefold=True)
except Exception:
    raise SystemExit(1)

def totp(step):
    msg = struct.pack(">Q", step)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 1_000_000).zfill(6)

current = epoch // 30
for delta in (-1, 0, 1):
    if hmac.compare_digest(totp(current + delta), code):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

remote_check_output() {
    local account="$1"
    local host="$2"
    local hex
    hex="$(account_hex "${account}")"

    ssh "${SSH_OPTS[@]}" "${host}" sh -s -- \
        "${account}" "${hex}" "${SECRET_DIR}" "${RUNTIME_OWNER}" "${RUNTIME_GROUP}" <<'REMOTE'
set -eu

account=$1
hex=$2
secret_dir=$3
expected_owner=$4
expected_group=$5
path="${secret_dir}/${hex}.totp"

printf '%s\n' "REMOTE_CHECK=STARTED"
printf '%s\n' "account=${account}"

if doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    mailbox list -u "${account}" 2>/dev/null | grep -Fxq INBOX
then
    printf '%s\n' "mailbox_exists=true"
else
    printf '%s\n' "mailbox_exists=false"
    printf '%s\n' "totp_exists=unknown"
    exit 4
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

    printf '%s\n' "owner=${owner}"
    printf '%s\n' "group=${group}"
    printf '%s\n' "mode=${mode}"

    if [ "${owner}" = "${expected_owner}" ] &&
       [ "${group}" = "${expected_group}" ] &&
       [ "${mode}" = "600" ]
    then
        printf '%s\n' "totp_metadata_safe=true"
    else
        printf '%s\n' "totp_metadata_safe=false"
        exit 5
    fi
else
    printf '%s\n' "totp_exists=false"
    printf '%s\n' "totp_metadata_safe=not_applicable"
fi

printf '%s\n' "REMOTE_CHECK=PASS"
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
    printf 'ERROR: remote check failed with status %s\n' "${rc}" >&2
    return "${rc}"
}

run_dry_run() {
    local account="$1"
    local host="$2"
    local output rc path

    validate_account "${account}"
    validate_host "${host}"
    require_command ssh
    require_command python3

    printf '%s\n' "program=${PROGRAM}"
    printf '%s\n' "operation=--dry-run"
    printf '%s\n' "account=${account}"
    printf '%s\n' "ssh_host=${host}"
    printf '%s\n' "TOTP_DRY_RUN=STARTED"
    printf '%s\n' "host=${host}"

    set +e
    output="$(remote_check_output "${account}" "${host}" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -ne 0 ]]; then
        printf '%s\n' "${output}" >&2
        printf 'ERROR: dry-run remote check failed with status %s\n' "${rc}" >&2
        return "${rc}"
    fi

    printf '%s\n' "ssh_connectivity=PASS"
    printf '%s\n' "${output}"

    if grep -Fxq 'totp_exists=true' <<<"${output}"; then
        printf '%s\n' "would_provision=false"
        printf '%s\n' "dry_run_disposition=existing_secret_refused"
        return 3
    fi

    grep -Fxq 'totp_exists=false' <<<"${output}" || {
        printf 'ERROR: dry-run could not establish active factor absence\n' >&2
        return 6
    }

    path="$(secret_path_for_account "${account}")"
    printf '%s\n' "planned_path=${path}"
    printf '%s\n' "secret_bytes=20"
    printf '%s\n' "atomic_no_overwrite=true"
    printf '%s\n' "preinstall_enrollment_verification=true"
    printf '%s\n' "failed_enrollment_rollback=true"
    printf '%s\n' "ambiguous_install_rollback=true"
    printf '%s\n' "would_provision=true"
    printf '%s\n' "TOTP_DRY_RUN=PASS"
}

prepare_enrollment_material() {
    local account="$1"
    local secret uri

    require_command python3 || return 1
    require_command qrencode || return 1

    WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/osmap-totp-enrollment.XXXXXXXX")" || return 1
    chmod 700 "${WORK_ROOT}" || return 1
    SECRET_FILE="${WORK_ROOT}/secret"
    URI_FILE="${WORK_ROOT}/otpauth-uri"

    secret="$(generate_secret)" || return 1
    uri="$(build_otpauth_uri "${account}" "${secret}")" || return 1

    printf '%s\n' "${secret}" > "${SECRET_FILE}" || return 1
    printf '%s\n' "${uri}" > "${URI_FILE}" || return 1
    chmod 600 "${SECRET_FILE}" "${URI_FILE}"
}

show_and_verify_enrollment() {
    local account="$1"
    local secret code

    [[ -r /dev/tty && -w /dev/tty ]] || {
        printf 'ERROR: enrollment requires an interactive /dev/tty\n' >&2
        return 1
    }

    secret="$(<"${SECRET_FILE}")"

    {
        printf '\n'
        printf '%s\n' "============================================================"
        printf '%s\n' "OSMAP TOTP ENROLLMENT"
        printf '%s\n' "============================================================"
        printf 'Account: %s\n' "${account}"
        printf '%s\n' "Scan this QR code with the intended authenticator:"
        printf '\n'
    } > /dev/tty

    qrencode -t ANSIUTF8 < "${URI_FILE}" > /dev/tty || return 1

    {
        printf '\n'
        printf '%s\n' "Manual enrollment secret, shown once:"
        printf '%s\n' "${secret}"
        printf '\n'
        printf '%s\n' "Before any server mutation, enter a current code from the enrolled authenticator."
    } > /dev/tty

    IFS= read -r -s -p "Current 6-digit TOTP code: " code < /dev/tty || return 1
    printf '\n' > /dev/tty

    if verify_totp_code "${secret}" "${code}"; then
        printf '%s\n' "TOTP_ENROLLMENT_VERIFICATION=PASS"
        printf '%s\n' "preinstall_enrollment_verification=PASS"
        printf '%s\n' "production_mutation_attempted=false"
        return 0
    fi

    printf 'ERROR: enrollment verification failed; no production mutation was attempted\n' >&2
    return 1
}

authorize_provision() {
    local account="$1"
    local answer

    [[ -r /dev/tty && -w /dev/tty ]] || {
        printf 'ERROR: production authorization requires /dev/tty\n' >&2
        return 1
    }

    printf '\nType exactly: PROVISION %s\n' "${account}" > /dev/tty
    IFS= read -r -p "Authorization: " answer < /dev/tty
    [[ "${answer}" == "PROVISION ${account}" ]] || {
        printf 'ERROR: production provisioning not authorized\n' >&2
        return 1
    }
    printf '%s\n' "operator_authorization=PASS"
}

remote_provision() {
    local account="$1"
    local host="$2"
    local candidate_file="$3"
    local expected_digest="$4"
    local hex
    hex="$(account_hex "${account}")"

    {
        cat <<'REMOTE_HEAD'
set -eu
umask 077

account=$1
hex=$2
secret_dir=$3
owner=$4
group=$5
expected_digest=$6
path="${secret_dir}/${hex}.totp"
input_tmp="$(mktemp /tmp/osmap-totp-input.XXXXXXXX)"
stage=""

cleanup() {
    rm -f "${input_tmp}" 2>/dev/null || true
    if [ -n "${stage}" ]; then
        doas rm -f "${stage}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM HUP

cat > "${input_tmp}" <<'OSMAP_TOTP_CANDIDATE_EOF'
REMOTE_HEAD
        cat "${candidate_file}"
        cat <<'REMOTE_TAIL'
OSMAP_TOTP_CANDIDATE_EOF
chmod 600 "${input_tmp}"

actual_digest="$(sha256 -q "${input_tmp}")"
[ "${actual_digest}" = "${expected_digest}" ] || {
    printf '%s\n' "REMOTE_PROVISION=FAILED_DIGEST"
    exit 7
}

if ! doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    mailbox list -u "${account}" 2>/dev/null | grep -Fxq INBOX
then
    printf '%s\n' "REMOTE_PROVISION=FAILED_MAILBOX"
    exit 4
fi

doas test -d "${secret_dir}" || {
    printf '%s\n' "REMOTE_PROVISION=FAILED_SECRET_DIR"
    exit 8
}

if doas test -e "${path}" 2>/dev/null; then
    printf '%s\n' "REMOTE_PROVISION=REFUSED_EXISTING"
    exit 3
fi

stage="$(doas mktemp "${secret_dir}/.osmap-totp-stage.XXXXXXXX")"
doas install -o "${owner}" -g "${group}" -m 600 "${input_tmp}" "${stage}"

stage_digest="$(doas sha256 -q "${stage}")"
[ "${stage_digest}" = "${expected_digest}" ] || {
    printf '%s\n' "REMOTE_PROVISION=FAILED_STAGE_DIGEST"
    exit 9
}

# Hard-linking the already permissioned staging inode to the final path is an
# atomic no-overwrite install. ln fails if the final path appeared concurrently.
if ! doas ln "${stage}" "${path}"; then
    printf '%s\n' "REMOTE_PROVISION=FAILED_NO_OVERWRITE_RACE"
    exit 10
fi

doas rm -f "${stage}"
stage=""

final_digest="$(doas sha256 -q "${path}")"
[ "${final_digest}" = "${expected_digest}" ] || {
    printf '%s\n' "REMOTE_PROVISION=FAILED_FINAL_DIGEST"
    exit 11
}

final_owner="$(doas stat -f '%Su' "${path}")"
final_group="$(doas stat -f '%Sg' "${path}")"
final_mode="$(doas stat -f '%Lp' "${path}")"

[ "${final_owner}" = "${owner}" ] &&
[ "${final_group}" = "${group}" ] &&
[ "${final_mode}" = "600" ] || {
    printf '%s\n' "REMOTE_PROVISION=FAILED_METADATA"
    exit 12
}

printf '%s\n' "REMOTE_PROVISION=STARTED"
printf '%s\n' "account=${account}"
printf '%s\n' "owner=${final_owner}"
printf '%s\n' "group=${final_group}"
printf '%s\n' "mode=${final_mode}"
printf '%s\n' "TOTP_PROVISIONING=PASS"
REMOTE_TAIL
    } | ssh "${SSH_OPTS[@]}" "${host}" sh -s -- \
        "${account}" "${hex}" "${SECRET_DIR}" "${RUNTIME_OWNER}" "${RUNTIME_GROUP}" "${expected_digest}"
}

reconcile_ambiguous_install() {
    local account="$1"
    local host="$2"
    local expected_digest="$3"
    local hex
    hex="$(account_hex "${account}")"

    ssh "${SSH_OPTS[@]}" "${host}" sh -s -- \
        "${account}" "${hex}" "${SECRET_DIR}" "${REVOKED_DIR}" \
        "${RUNTIME_OWNER}" "${RUNTIME_GROUP}" "${expected_digest}" <<'REMOTE'
set -eu

account=$1
hex=$2
secret_dir=$3
revoked_dir=$4
owner=$5
group=$6
expected_digest=$7
path="${secret_dir}/${hex}.totp"

printf '%s\n' "REMOTE_RECONCILE=STARTED"
printf '%s\n' "account=${account}"

if ! doas test -e "${path}" 2>/dev/null; then
    printf '%s\n' "reconcile_active_factor=absent"
    printf '%s\n' "ambiguous_install_rollback=not_required"
    printf '%s\n' "REMOTE_RECONCILE=PASS"
    exit 0
fi

if doas test -L "${path}" 2>/dev/null || ! doas test -f "${path}" 2>/dev/null; then
    printf '%s\n' "reconcile_active_factor=unsafe_file_type"
    printf '%s\n' "manual_review_required=true"
    exit 20
fi

current_owner="$(doas stat -f '%Su' "${path}")"
current_group="$(doas stat -f '%Sg' "${path}")"
current_mode="$(doas stat -f '%Lp' "${path}")"
current_digest="$(doas sha256 -q "${path}")"

if [ "${current_owner}" != "${owner}" ] ||
   [ "${current_group}" != "${group}" ] ||
   [ "${current_mode}" != "600" ] ||
   [ "${current_digest}" != "${expected_digest}" ]
then
    printf '%s\n' "reconcile_active_factor=nonmatching"
    printf '%s\n' "manual_review_required=true"
    printf '%s\n' "rollback_performed=false"
    exit 21
fi

# The active file is byte-for-byte the attempted candidate and has the expected
# metadata. Quarantine it instead of deleting it. Never touch a nonmatching
# factor during ambiguity recovery.
doas install -d -o "${owner}" -g "${group}" -m 700 "${revoked_dir}"
stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
quarantine="${revoked_dir}/${hex}.${stamp}.ambiguous.totp"

if doas test -e "${quarantine}" 2>/dev/null; then
    printf '%s\n' "manual_review_required=true"
    printf '%s\n' "rollback_performed=false"
    exit 22
fi

doas mv "${path}" "${quarantine}"
doas chmod 600 "${quarantine}"
doas chown "${owner}:${group}" "${quarantine}"

printf '%s\n' "reconcile_active_factor=matching_candidate"
printf '%s\n' "ambiguous_install_rollback=PASS"
printf '%s\n' "revoke_quarantine=PASS"
printf '%s\n' "rollback_performed=true"
printf '%s\n' "REMOTE_RECONCILE=PASS"
REMOTE
}

run_provision() {
    local account="$1"
    local host="$2"
    local secret expected_digest output rc

    validate_account "${account}"
    validate_host "${host}"
    require_command ssh
    require_command python3
    require_command qrencode
    require_command sha256sum

    printf '%s\n' "program=${PROGRAM}"
    printf '%s\n' "operation=--provision"
    printf '%s\n' "account=${account}"
    printf '%s\n' "ssh_host=${host}"
    printf '%s\n' "TOTP_PROVISIONING_WORKFLOW=STARTED"
    printf '%s\n' "host=${host}"
    printf '%s\n' "qrencode_preflight=PASS"
    printf 'qrencode_path=%s\n' "$(command -v qrencode)"
    qrencode --version 2>&1 | head -n 1

    set +e
    run_dry_run "${account}" "${host}"
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then
        if [[ "${rc}" -eq 3 ]]; then
            printf '%s\n' "existing_factor_provision_refusal=PASS"
        fi
        return "${rc}"
    fi

    prepare_enrollment_material "${account}"
    show_and_verify_enrollment "${account}"
    authorize_provision "${account}"

    secret="$(<"${SECRET_FILE}")"
    printf '# %s\nsecret=%s\n' "${account}" "${secret}" > "${WORK_ROOT}/candidate.totp"
    chmod 600 "${WORK_ROOT}/candidate.totp"
    expected_digest="$(sha256sum "${WORK_ROOT}/candidate.totp" | awk '{print $1}')"

    set +e
    output="$(remote_provision "${account}" "${host}" "${WORK_ROOT}/candidate.totp" "${expected_digest}" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
        printf '%s\n' "ssh_connectivity=PASS"
        printf '%s\n' "${output}"
        printf '%s\n' "production_mutation_attempted=true"
        printf '%s\n' "account=${account}"
        printf '%s\n' "TOTP_PROVISIONING_WORKFLOW=PASS"
        printf '%s\n' "provision_status=PASS"
        printf '%s\n' "automatic_provision_retry=false"
        return 0
    fi

    printf '%s\n' "${output}" >&2
    printf '%s\n' "production_mutation_attempted=true"
    printf '%s\n' "automatic_provision_retry=false"
    printf 'WARNING: provisioning result was non-success; reconciling without retry after %s seconds\n' \
        "${AMBIGUOUS_RECONCILE_DELAY}" >&2

    sleep "${AMBIGUOUS_RECONCILE_DELAY}"

    set +e
    output="$(reconcile_ambiguous_install "${account}" "${host}" "${expected_digest}" 2>&1)"
    local reconcile_rc=$?
    set -e
    printf '%s\n' "${output}" >&2

    if [[ "${reconcile_rc}" -eq 0 ]]; then
        printf 'ERROR: provisioning did not complete cleanly; matching ambiguous state was reconciled\n' >&2
        return 23
    fi

    printf 'ERROR: provisioning outcome requires manual review; no automatic retry was performed\n' >&2
    return 24
}

self_test() {
    local tmp s1 s2 hex code source

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

    hex="$(account_hex 'alice@example.com')"
    [[ "${hex}" == "616c696365406578616d706c652e636f6d" ]]
    printf '%s\n' "hex_encoding=PASS"

    s1="$(generate_secret)"
    s2="$(generate_secret)"
    [[ "${s1}" =~ ^[A-Z2-7]{32}$ ]]
    [[ "${s2}" =~ ^[A-Z2-7]{32}$ ]]
    [[ "${s1}" != "${s2}" ]]
    printf '%s\n' "unique_secret_generation=PASS"

    tmp="$(mktemp -d)"
    chmod 700 "${tmp}"
    printf '%s\n' "${s1}" > "${tmp}/secret"
    chmod 600 "${tmp}/secret"
    [[ "$(stat -c '%a' "${tmp}")" == "700" ]]
    [[ "$(stat -c '%a' "${tmp}/secret")" == "600" ]]
    rm -rf "${tmp}"
    printf '%s\n' "owner_only_local_mode=PASS"

    code="$(totp_code "${s1}" 1234567890 6)"
    verify_totp_code "${s1}" "${code}" 1234567890
    if verify_totp_code "${s1}" '000000' 1234567890 >/dev/null 2>&1 &&
       [[ "${code}" != "000000" ]]
    then
        printf 'SELF_TEST=FAIL invalid TOTP accepted\n' >&2
        return 1
    fi
    printf '%s\n' "current_totp_verification=PASS"

    code="$(totp_code 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' 59 6)"
    [[ "${code}" == "287082" ]]
    printf '%s\n' "rfc6238_reference=PASS"

    source="$(<"$0")"
    [[ "${source}" == *"show_and_verify_enrollment \"\${account}\""* ]]
    [[ "${source}" == *"authorize_provision \"\${account}\""* ]]
    [[ "${source}" == *"remote_provision \"\${account}\""* ]]
    printf '%s\n' "preinstall_enrollment_verification_order=PASS"

    [[ "${source}" == *'require_command qrencode'* ]]
    [[ "${source}" == *"prepare_enrollment_material \"\${account}\""* ]]
    printf '%s\n' "qrencode_fail_closed_order=PASS"

    [[ "${source}" == *'automatic_provision_retry=false'* ]]
    [[ "${source}" == *'reconcile_ambiguous_install'* ]]
    [[ "${source}" == *"[ \"\${current_digest}\" != \"\${expected_digest}\" ]"* ]]
    printf '%s\n' "ambiguous_provision_rollback_order=PASS"



    printf '%s\n' "SELF_TEST=PASS"
}

# The lifecycle coordinator reuses enrollment and no-overwrite installation.
# Sourcing must not dispatch an operation; standalone CLI behavior is unchanged.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

operation=""
account=""
host="${DEFAULT_HOST}"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --check|--dry-run|--provision|--self-test)
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
    --provision)
        [[ -n "${account}" ]] || usage
        run_provision "${account}" "${host}"
        ;;
    *)
        usage
        ;;
esac
