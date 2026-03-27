# OSMAP QEMU Lab

This directory contains project-local QEMU infrastructure for OSMAP validation.

The design goal is reuse, not reinvention. These scripts wrap the OpenBSD lab
model under `/home/foo/Workspace/openbsd-self-hosting/maint/qemu` and apply
OSMAP-specific defaults so auth-path and runtime validation can be reproduced
from inside this repository.

## Default Layout

The wrappers use `/tmp/osmap-qemu` by default for:

- OpenBSD install media cache
- base images
- overlays
- run logs

That keeps the first lab workflow self-contained and avoids assuming a
pre-existing `/home/foo/VMs` layout.

## Scripts

- `osmap-qemu-build.ksh`
  Builds a fresh OpenBSD 7.8 base image using the upstream unattended install
  model.
- `osmap-qemu-validate-auth.ksh`
  Boots an overlay from the base image, syncs the OSMAP repository into the VM,
  and runs the Rust test suite with QEMU-safe Cargo paths.

## Requirements

The wrappers assume the upstream OpenBSD lab scripts exist at:

- `/home/foo/Workspace/openbsd-self-hosting/maint/qemu`

Override that path with `OPENBSD_SELF_HOSTING_QEMU_DIR` if needed.

## Typical Flow

```sh
ksh maint/qemu/osmap-qemu-build.ksh
ksh maint/qemu/osmap-qemu-validate-auth.ksh
```

These scripts are intentionally narrow. They are here to validate OSMAP, not to
replace the broader mail-lab orchestration in the upstream project.
