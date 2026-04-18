# Mail Host Service Activation SOP

## Purpose

This document is the operator procedure for rehearsing or applying the reviewed
OSMAP service-activation path on `mail.blackbagsecurity.com` from the standard
host checkout at `~/OSMAP`.

It is paired with:

- `maint/live/osmap-live-rehearse-service-activation.ksh`
- `maint/live/osmap-live-validate-service-enablement.ksh`
- `MAIL_HOST_SERVICE_ARTIFACTS_SOP.md`
- `MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`

The goal is to isolate the final runtime step after binary install,
runtime-group provisioning, and reviewed service-artifact installation are
already complete: create the reviewed state/runtime directories, start
`osmap_mailbox_helper` and `osmap_serve`, and immediately rerun the repo-owned
service validator.

## Standard Host And Access Path

- host: `mail.blackbagsecurity.com`
- operator access: `ssh mail`
- standard checkout: `~/OSMAP`

## Required Preconditions

Before a real apply run, all of the following must already be true:

- the reviewed target snapshot is synced into `~/OSMAP`
- the host already has `/usr/local/bin/osmap`
- the host already has `osmaprt` and `_osmap` membership in that group
- the host already has the reviewed `/etc/osmap`, `/usr/local/libexec/osmap`,
  and `/etc/rc.d` service artifacts installed

This SOP is intentionally the final runtime step, not the place to recover
missing binary, group, or service-artifact prerequisites.

## Standard Rehearsal Flow

1. Sync `~/OSMAP` to the reviewed `origin/main` snapshot.
2. Run the host-side rehearsal wrapper:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-service-activation.ksh
```

The wrapper creates a timestamped session under `~/osmap-service-activation/`
that contains:

- `scripts/apply-service-activation.sh`
- `scripts/restore-service-activation.sh`
- `reports/service-enablement-after-service-activation.txt`
- `service-activation-session.txt`

The rehearsal mode does not modify the live host. It prepares the exact
runtime-activation and stop commands for a later reviewed apply run.

## Standard Apply Flow

After reviewing the generated session contents:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-service-activation.ksh --mode apply --session-dir "$HOME/osmap-service-activation/<session>"
```

That mode runs the generated `apply-service-activation.sh`, which:

- confirms the reviewed binary, shared runtime group, and service artifacts are
  present
- normalizes the service env file group ownership so `_osmap` and `vmail` can
  read their respective env files without widening privilege
- removes stale exact-match OSMAP processes and stale `/var/run/rc.d/` runfiles
  from earlier failed attempts before the clean startup sequence begins
- creates the reviewed `_osmap` and `vmail` state/runtime directories with the
  expected ownership and modes
- starts and checks `osmap_mailbox_helper`
- starts and checks `osmap_serve`
- immediately reruns
  `ksh ./maint/live/osmap-live-validate-service-enablement.ksh`
- requires the validator report to stop reporting:
  - `mailbox_helper_service_not_healthy`
  - `serve_service_not_healthy`
  - `missing_helper_socket`
  - `loopback_http_listener_not_ready`

## Standard Restore Flow

If the service-activation attempt must be reversed:

```sh
ssh mail
sh "$HOME/osmap-service-activation/<session>/scripts/restore-service-activation.sh"
```

That script stops `osmap_serve` and `osmap_mailbox_helper` and removes the
helper socket and stale `/var/run/rc.d/` service runfiles if they still exist.
It intentionally leaves the created
state/runtime directories in place so operators can inspect them before manual
cleanup.

## Required Post-Apply Checks

After a real apply run, inspect the generated validator report:

```sh
cd ~/OSMAP
sed -n '1,120p' "$HOME/osmap-service-activation/<session>/reports/service-enablement-after-service-activation.txt"
```

The minimum expected result for this gate is the absence of the four
runtime-health failures listed above.

The current repo-owned host artifacts for this gate should be archived at:

- `maint/live/latest-host-service-activation-session.txt`
- `maint/live/latest-host-service-enablement-report.txt`
