#!/bin/sh
#
# Build a reusable OpenBSD lab base image for OSMAP validation.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/osmap-qemu-common.ksh"

require_upstream_script "${OPENBSD_LAB_BUILD_SCRIPT}"
require_runtime_ksh

log "building the current stable OpenBSD base image for OSMAP validation"
exec ksh "${OPENBSD_SELF_HOSTING_QEMU_DIR}/${OPENBSD_LAB_BUILD_SCRIPT}" \
  --iso-dir "${ISO_DIR}" \
  --disk "${BASE_IMAGE}" \
  --qemu-mem "${QEMU_MEM}" \
  --qemu-smp "${QEMU_SMP}"
