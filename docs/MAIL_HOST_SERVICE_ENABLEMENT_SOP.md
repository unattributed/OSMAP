# Mail Host Service Enablement SOP

## Purpose

This document is the operator procedure for rehearsing or applying the reviewed
split-runtime OSMAP service install on `mail.blackbagsecurity.com` from the
standard host checkout at `~/OSMAP`.

It is paired with:

- `maint/live/osmap-live-rehearse-binary-deployment.ksh`
- `maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh`
- `maint/live/osmap-live-rehearse-service-enablement.ksh`
- `maint/live/osmap-live-validate-service-enablement.ksh`
- `MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
- `MAIL_HOST_RUNTIME_GROUP_PROVISIONING_SOP.md`
- `maint/openbsd/README.md`
- `maint/openbsd/mail.blackbagsecurity.com/`

The goal is to make the host-side `_osmap` plus `vmail` service install
reviewable and repeatable before the public-edge cutover is attempted.

## Standard Host And Access Path

- host: `mail.blackbagsecurity.com`
- operator access: `ssh mail`
- standard checkout: `~/OSMAP`

## Required Preconditions

Before a real apply run, all of the following must already be true:

- the reviewed target snapshot is synced into `~/OSMAP`
- the `_osmap` and `vmail` users already exist
- the reviewed binary-deployment path has already cleared the
  `/usr/local/bin/osmap` prerequisite
- the reviewed runtime-group provisioning path has already created the
  dedicated helper-socket group and added `_osmap` to it

The binary prerequisite is handled separately by `MAIL_HOST_BINARY_DEPLOYMENT_SOP.md`
and `maint/live/osmap-live-rehearse-binary-deployment.ksh`.
The runtime-group prerequisite is handled separately by
`MAIL_HOST_RUNTIME_GROUP_PROVISIONING_SOP.md` and
`maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh`.

For the reviewed `mail.blackbagsecurity.com` service path, the wrapper defaults
that dedicated shared runtime group to `osmaprt`.

Do not satisfy this by adding `_osmap` to `vmail`.

## Standard Rehearsal Flow

1. Sync `~/OSMAP` to the reviewed `origin/main` snapshot.
2. Run the host-side rehearsal wrapper:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-service-enablement.ksh
```

The wrapper creates a timestamped session under `~/osmap-service-enablement/`
that contains:

- `backup/` with any current live service files copied from `/etc` and
  `/usr/local/libexec`
- `staged/` with the reviewed repo-owned service files
- `scripts/apply-service-enablement.sh`
- `scripts/restore-service-enablement.sh`
- `service-enablement-session.txt`

The rehearsal mode does not modify the live host. It prepares the exact
commands for a later reviewed apply run.

## Standard Apply Flow

After reviewing the generated session contents:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-service-enablement.ksh --mode apply --session-dir "$HOME/osmap-service-enablement/<session>"
```

That mode runs the generated `apply-service-enablement.sh`, which:

- checks for `_osmap`, `vmail`, and the dedicated shared runtime group
- checks that `_osmap` is in that shared runtime group
- installs the reviewed env, launcher, and `rc.d` files
- creates the reviewed state directories for `_osmap` and `vmail`
- starts and checks `osmap_mailbox_helper`
- starts and checks `osmap_serve`

## Standard Restore Flow

If the service install must be reversed:

```sh
ssh mail
sh "$HOME/osmap-service-enablement/<session>/scripts/restore-service-enablement.sh"
```

That script stops the OSMAP services, restores any backed-up service files, and
removes the newly installed service files that did not exist before the apply
run. It intentionally leaves any created state directories in place so
operators can inspect them before manual cleanup.

## Required Post-Apply Checks

After a real apply run, do not stop at `rcctl start`. Also run:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-service-enablement.ksh
```

The repo-owned validator confirms:

- `/usr/local/bin/osmap` exists
- the shared helper-socket runtime group exists
- `_osmap` is in that group without being widened into `vmail`
- the reviewed env, launcher, and `rc.d` files are installed
- `rcctl check osmap_mailbox_helper` passes
- `rcctl check osmap_serve` passes
- the helper socket exists
- `127.0.0.1:8080` is actually listening

Before the public browser edge is cut over, also run the edge and readiness
checks that depend on this persistent service install:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-service-enablement.ksh
ksh ./maint/live/osmap-live-validate-edge-cutover.ksh
ksh ./maint/live/osmap-live-assess-internet-exposure.ksh
ksh ./maint/live/osmap-live-validate-v2-readiness.ksh
```

The current repo-owned host report artifact for this gate should be archived at:

- `maint/live/latest-host-service-enablement-report.txt`
