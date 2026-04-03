#!/bin/sh
#
# Run the repo-owned validation gate from a persistent host-side checkout.
#
# This is intended for a clean clone such as ~/OSMAP on
# mail.blackbagsecurity.com, where /tmp may be too small or crowded for repeat
# Rust builds. The script keeps temporary, cargo-home, and target paths under
# the caller's home directory so live validation remains reproducible without
# depending on system-wide temp space.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOST_VALIDATION_ROOT="${OSMAP_HOST_VALIDATION_ROOT:-${HOME}/tmp-osmap-host-validation}"
TMPDIR_PATH="${HOST_VALIDATION_ROOT}/tmp"
CARGO_HOME_PATH="${HOST_VALIDATION_ROOT}/cargo-home"
CARGO_TARGET_DIR_PATH="${HOST_VALIDATION_ROOT}/target"

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

require_tool cargo
require_tool mkdir

mkdir -p "${TMPDIR_PATH}" "${CARGO_HOME_PATH}" "${CARGO_TARGET_DIR_PATH}"

cd "${PROJECT_ROOT}"

if [ "$#" -eq 0 ]; then
  set -- make security-check
fi

log "running host validation from ${PROJECT_ROOT}"
log "using TMPDIR=${TMPDIR_PATH}"
log "using CARGO_HOME=${CARGO_HOME_PATH}"
log "using CARGO_TARGET_DIR=${CARGO_TARGET_DIR_PATH}"

exec env \
  TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  "$@"
