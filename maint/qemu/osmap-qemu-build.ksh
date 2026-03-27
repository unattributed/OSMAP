#!/bin/sh
#
# Build a reusable OpenBSD lab base image for OSMAP validation.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/osmap-qemu-common.ksh"

require_upstream_script "lab-openbsd78-build.ksh"
require_runtime_ksh

log "building OpenBSD 7.8 base image for OSMAP validation"
exec ksh "${OPENBSD_SELF_HOSTING_QEMU_DIR}/lab-openbsd78-build.ksh" \
  --iso-dir "${ISO_DIR}" \
  --disk "${BASE_IMAGE}" \
  --qemu-mem "${QEMU_MEM}" \
  --qemu-smp "${QEMU_SMP}"
