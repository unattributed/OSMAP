# Mail Host Binary Deployment SOP

## Purpose

This document is the operator procedure for rehearsing or applying the reviewed
OSMAP binary install on `mail.blackbagsecurity.com` from the standard host
checkout at `~/OSMAP`.

It is paired with:

- `maint/live/osmap-live-rehearse-binary-deployment.ksh`
- `maint/live/osmap-live-validate-service-enablement.ksh`
- `MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`

The goal is to make the `/usr/local/bin/osmap` install reviewable and
repeatable before the split `_osmap` plus `vmail` service install is applied.

## Standard Host And Access Path

- host: `mail.blackbagsecurity.com`
- operator access: `ssh mail`
- standard checkout: `~/OSMAP`

## Why This Exists

The current service-enablement gate on `mail.blackbagsecurity.com` failed first
at `/usr/local/bin/osmap`. That binary must exist and be executable before the
repo-owned service install path can succeed.

This SOP isolates that one prerequisite so operators can clear it without
improvising build, install, backup, or restore commands on the live host.

## Required Preconditions

Before a real apply run, all of the following must already be true:

- the reviewed target snapshot is synced into `~/OSMAP`
- the host has `cargo`, `rustc`, `install`, `ksh`, and `doas`
- the host has enough local disk space for a session-local cargo target tree
- operators are prepared to keep the generated session directory until the
  service-enablement path has been reviewed or reversed

This wrapper defaults to a session-local debug build because the current repo
already uses that profile for live validation on the validated host.

## Standard Rehearsal Flow

1. Sync `~/OSMAP` to the reviewed `origin/main` snapshot.
2. Run the host-side rehearsal wrapper:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-binary-deployment.ksh
```

The wrapper creates a timestamped session under `~/osmap-binary-deployment/`
that contains:

- `backup/` with any current live `/usr/local/bin/osmap`
- `staged/usr/local/bin/osmap` built from the reviewed host checkout
- `scripts/apply-binary-deployment.sh`
- `scripts/restore-binary-deployment.sh`
- `reports/service-enablement-after-binary-install.txt`
- `binary-deployment-session.txt`

The rehearsal mode does not modify the live host. It prepares the exact apply
and restore commands around one reviewed staged binary.

## Standard Apply Flow

After reviewing the generated session contents:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-binary-deployment.ksh --mode apply --session-dir "$HOME/osmap-binary-deployment/<session>"
```

That mode runs the generated `apply-binary-deployment.sh`, which:

- installs the staged binary into `/usr/local/bin/osmap`
- validates that `/usr/local/bin/osmap` is executable
- immediately reruns
  `ksh ./maint/live/osmap-live-validate-service-enablement.ksh`
- requires the validator report to show `service_binary_state=installed`
- requires the validator report to stop reporting `missing_osmap_binary`

This is intentionally narrower than the full service gate. The binary apply can
be accepted as successful even if the validator still fails on later service
preconditions such as the shared runtime group, env files, launchers, `rc.d`
files, helper socket, or loopback listener.

## Standard Restore Flow

If the binary install must be reversed:

```sh
ssh mail
sh "$HOME/osmap-binary-deployment/<session>/scripts/restore-binary-deployment.sh"
```

That script restores the prior `/usr/local/bin/osmap` if one existed, or
removes the installed binary if the host had no previous copy.

## Required Post-Apply Checks

After a real apply run, inspect the generated validator report before moving to
service installation:

```sh
cd ~/OSMAP
sed -n '1,80p' "$HOME/osmap-binary-deployment/<session>/reports/service-enablement-after-binary-install.txt"
```

The minimum expected result for this gate is:

- `service_binary_state=installed`
- no `missing_osmap_binary` entry under `failed_checks`

The full service-enablement gate still has to be cleared separately through
`MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`.
