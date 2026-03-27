#!/bin/sh
#
# Shared defaults for OSMAP's project-local QEMU validation wrappers.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OPENBSD_SELF_HOSTING_QEMU_DIR="${OPENBSD_SELF_HOSTING_QEMU_DIR:-/home/foo/Workspace/openbsd-self-hosting/maint/qemu}"
LAB_ROOT="${LAB_ROOT:-/tmp/osmap-qemu}"
ISO_DIR="${ISO_DIR:-${LAB_ROOT}/iso}"
BASE_IMAGE="${BASE_IMAGE:-${LAB_ROOT}/disk-lab-openbsd78-base.qcow2}"
OVERLAY_IMAGE="${OVERLAY_IMAGE:-${LAB_ROOT}/disk-lab-osmap-auth-overlay.qcow2}"
RUN_LOG="${RUN_LOG:-${LAB_ROOT}/osmap-qemu.log}"
SSH_PORT="${SSH_PORT:-2242}"
SSH_USER="${SSH_USER:-foo}"
SSH_HOST="${SSH_HOST:-127.0.0.1}"
TMUX_SESSION="${TMUX_SESSION:-osmap-qemu}"
VM_NAME="${VM_NAME:-osmap-auth-validation}"
QEMU_MEM="${QEMU_MEM:-4096}"
QEMU_SMP="${QEMU_SMP:-2}"

mkdir -p "${LAB_ROOT}" "${ISO_DIR}"

ts() {
  date -u +'%Y-%m-%d %H:%M:%S UTC'
}

log() {
  _line="[$(ts)] [osmap-qemu] $*"
  print -- "${_line}"
  print -- "${_line}" >> "${RUN_LOG}"
}

require_upstream_script() {
  _path="${OPENBSD_SELF_HOSTING_QEMU_DIR}/$1"
  [ -f "${_path}" ] || {
    printf '%s\n' "missing upstream qemu helper: ${_path}" >&2
    exit 1
  }
}

require_qemu_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '%s\n' "required tool not found: $1" >&2
    exit 1
  }
}

require_runtime_ksh() {
  command -v ksh >/dev/null 2>&1 || {
    printf '%s\n' "runtime requires ksh for the upstream OpenBSD lab scripts" >&2
    exit 1
  }
}
