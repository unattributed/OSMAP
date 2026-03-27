#!/bin/sh
#
# Boot an OSMAP OpenBSD lab VM and run the auth/TOTP validation suite.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/osmap-qemu-common.ksh"

require_upstream_script "lab-ssh-guard.ksh"
require_runtime_ksh
require_qemu_tool "qemu-system-x86_64"
require_qemu_tool "qemu-img"
require_qemu_tool "tmux"

[ -f "${BASE_IMAGE}" ] || {
  log "base image missing, invoking build wrapper first"
  ksh "${SCRIPT_DIR}/osmap-qemu-build.ksh"
}

SSH_GUARD_USER="${SSH_USER}"
SSH_GUARD_HOST="${SSH_HOST}"
SSH_GUARD_PORT="${SSH_PORT}"
SSH_GUARD_CONTROL_PATH="/tmp/${TMUX_SESSION}-ssh-control.sock"
SSH_GUARD_CONNECT_TIMEOUT=5
SSH_GUARD_SERVER_ALIVE_INTERVAL=10
SSH_GUARD_SERVER_ALIVE_COUNT_MAX=3
SSH_GUARD_CONTROL_PERSIST=900
SSH_GUARD_WAIT_TRIES=120
SSH_GUARD_WAIT_SLEEP=6
SSH_GUARD_READY_STABLE_COUNT=1
SSH_GUARD_BOOT_GRACE=18
SSH_GUARD_MAX_CLOSE_WAIT=64
SSH_GUARD_MAX_FIN_WAIT2=64

. "${OPENBSD_SELF_HOSTING_QEMU_DIR}/lab-ssh-guard.ksh"

cleanup() {
  ssh_guard_close_master || true
  tmux kill-session -t "${TMUX_SESSION}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

rm -f "${OVERLAY_IMAGE}"
qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${OVERLAY_IMAGE}" >/dev/null

_qemu_cmd="qemu-system-x86_64 -enable-kvm -name ${VM_NAME} -m ${QEMU_MEM} -smp ${QEMU_SMP} -drive file=${OVERLAY_IMAGE},if=virtio,format=qcow2 -netdev user,id=net0,net=192.168.1.0/24,dhcpstart=192.168.1.44,hostfwd=tcp::${SSH_PORT}-:22 -device e1000,netdev=net0 -boot order=c -nographic"
tmux kill-session -t "${TMUX_SESSION}" 2>/dev/null || true
tmux new-session -d -s "${TMUX_SESSION}" "${_qemu_cmd}"
log "booted validation overlay ${OVERLAY_IMAGE} on ssh port ${SSH_PORT}"

ssh_guard_wait_ready
ssh_guard_open_master

log "syncing OSMAP repository into the QEMU guest"
tar -C "$(dirname "${PROJECT_ROOT}")" \
  --exclude='.git' \
  --exclude='target' \
  -cf - "$(basename "${PROJECT_ROOT}")" | \
  ssh_guard_pipe_to_remote "rm -rf /home/foo/osmap-qemu-validation && tar -C /home/foo -xf - && mv /home/foo/$(basename "${PROJECT_ROOT}") /home/foo/osmap-qemu-validation"

log "running Rust auth/TOTP validation suite inside the QEMU guest"
ssh_guard_run "cd /home/foo/osmap-qemu-validation && CARGO_HOME=/tmp/osmap-cargo-home CARGO_TARGET_DIR=/tmp/osmap-target cargo test"

log "QEMU auth validation completed successfully"
