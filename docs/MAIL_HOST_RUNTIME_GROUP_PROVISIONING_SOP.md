# Mail Host Runtime Group Provisioning SOP

## Purpose

This document is the operator procedure for rehearsing or applying the reviewed
shared-runtime-group provisioning on `mail.blackbagsecurity.com` from the
standard host checkout at `~/OSMAP`.

It is paired with:

- `maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh`
- `maint/live/osmap-live-validate-service-enablement.ksh`
- `MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`

The goal is to make creation of `osmaprt` and `_osmap` membership in that
group reviewable and reversible before the split `_osmap` plus `vmail` service
install is applied.

## Standard Host And Access Path

- host: `mail.blackbagsecurity.com`
- operator access: `ssh mail`
- standard checkout: `~/OSMAP`

## Why This Exists

After the binary install was cleared, the next service-enablement blocker was
the missing shared runtime group for the helper socket path and the missing
membership for `_osmap`.

This SOP isolates that one prerequisite so operators can clear it without
widening `_osmap` into `vmail`, hand-editing `/etc/group`, or improvising
rollback steps on the live host.

## Required Preconditions

Before a real apply run, all of the following must already be true:

- the reviewed target snapshot is synced into `~/OSMAP`
- the host already has `/usr/local/bin/osmap`
- the target `_osmap` user already exists
- the host has `groupadd`, `groupdel`, `usermod`, `ksh`, and `doas`
- operators are prepared to keep the generated session directory until the
  service-enablement path has been reviewed or reversed

## Standard Rehearsal Flow

1. Sync `~/OSMAP` to the reviewed `origin/main` snapshot.
2. Run the host-side rehearsal wrapper:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh
```

The wrapper creates a timestamped session under `~/osmap-runtime-group/` that
contains:

- `scripts/apply-runtime-group-provisioning.sh`
- `scripts/restore-runtime-group-provisioning.sh`
- `reports/service-enablement-after-runtime-group.txt`
- `runtime-group-session.txt`

The rehearsal mode does not modify the live host. It prepares the exact group
commands for a later reviewed apply run.

## Standard Apply Flow

After reviewing the generated session contents:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh --mode apply --session-dir "$HOME/osmap-runtime-group/<session>"
```

That mode runs the generated `apply-runtime-group-provisioning.sh`, which:

- creates `osmaprt` if it does not already exist
- appends `_osmap` to `osmaprt` without widening `_osmap` into `vmail`
- immediately reruns
  `ksh ./maint/live/osmap-live-validate-service-enablement.ksh`
- requires the validator report to stop reporting
  `missing_shared_runtime_group`
- requires the validator report to stop reporting
  `osmap_user_missing_shared_runtime_group_membership`

This is intentionally narrower than the full service gate. The apply can be
accepted as successful even if the validator still fails on later service
preconditions such as env files, launchers, `rc.d` files, helper socket, or
loopback listener.

## Standard Restore Flow

If the runtime-group change must be reversed:

```sh
ssh mail
sh "$HOME/osmap-runtime-group/<session>/scripts/restore-runtime-group-provisioning.sh"
```

That script restores the original supplementary-group set for `_osmap`. If the
wrapper created `osmaprt` during the apply run, the restore path also removes
that group.

## Required Post-Apply Checks

After a real apply run, inspect the generated validator report before moving to
service installation:

```sh
cd ~/OSMAP
sed -n '1,80p' "$HOME/osmap-runtime-group/<session>/reports/service-enablement-after-runtime-group.txt"
```

The minimum expected result for this gate is:

- no `missing_shared_runtime_group` entry under `failed_checks`
- no `osmap_user_missing_shared_runtime_group_membership` entry under
  `failed_checks`
- `shared_group_line=` reflects `osmaprt`
- `osmap_group_membership=` includes `osmaprt`

The full service-enablement gate still has to be cleared separately through
`MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`.
