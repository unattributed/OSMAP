# Mail Host Service Artifacts SOP

## Purpose

This document is the operator procedure for rehearsing or applying the reviewed
OSMAP service artifacts on `mail.blackbagsecurity.com` from the standard host
checkout at `~/OSMAP`.

It is paired with:

- `maint/live/osmap-live-rehearse-service-artifacts.ksh`
- `maint/live/osmap-live-validate-service-enablement.ksh`
- `MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`

The goal is to make the reviewed `/etc/osmap`, `/usr/local/libexec/osmap`, and
`/etc/rc.d` files reviewable and repeatable before the later service-start and
state-directory work is applied.

## Standard Host And Access Path

- host: `mail.blackbagsecurity.com`
- operator access: `ssh mail`
- standard checkout: `~/OSMAP`

## Why This Exists

After the binary and shared-runtime-group steps were cleared, the next service
validator failures were the missing reviewed env files, launchers, and `rc.d`
scripts.

This SOP isolates those artifact installs so operators can clear them without
mixing in service startup, helper-socket creation, or loopback-listener
expectations in the same host-side change stream.

## Required Preconditions

Before a real apply run, all of the following must already be true:

- the reviewed target snapshot is synced into `~/OSMAP`
- the host already has `/usr/local/bin/osmap`
- the host already has `osmaprt` and `_osmap` membership in that group
- the host has `install`, `ksh`, and `doas`

## Standard Rehearsal Flow

1. Sync `~/OSMAP` to the reviewed `origin/main` snapshot.
2. Run the host-side rehearsal wrapper:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-service-artifacts.ksh
```

The wrapper creates a timestamped session under `~/osmap-service-artifacts/`
that contains:

- `backup/` with any current live service artifact files
- `staged/` with the reviewed repo-owned replacements
- `scripts/apply-service-artifacts.sh`
- `scripts/restore-service-artifacts.sh`
- `reports/service-enablement-after-service-artifacts.txt`
- `service-artifacts-session.txt`

The rehearsal mode does not modify the live host. It prepares the exact
artifact install and restore commands for a later reviewed apply run.

## Standard Apply Flow

After reviewing the generated session contents:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-service-artifacts.ksh --mode apply --session-dir "$HOME/osmap-service-artifacts/<session>"
```

That mode runs the generated `apply-service-artifacts.sh`, which:

- installs the reviewed env files into `/etc/osmap`
- installs the reviewed launchers into `/usr/local/libexec/osmap`
- installs the reviewed `rc.d` files into `/etc/rc.d`
- restores reviewed stderr capture into the configured audit-log files instead
  of leaving both services pointed at `/dev/null`
- immediately reruns
  `ksh ./maint/live/osmap-live-validate-service-enablement.ksh`
- requires the validator report to stop reporting:
  - `missing_serve_env_file`
  - `missing_helper_env_file`
  - `missing_serve_launcher`
  - `missing_helper_launcher`
  - `missing_serve_rc_script`
  - `missing_helper_rc_script`

This is intentionally narrower than the full service gate. The artifact apply
can be accepted as successful even if the validator still fails on service
health, helper socket presence, or loopback listener readiness.

## Standard Restore Flow

If the service artifact install must be reversed:

```sh
ssh mail
sh "$HOME/osmap-service-artifacts/<session>/scripts/restore-service-artifacts.sh"
```

That script restores any backed-up service artifacts and removes newly
installed reviewed files that did not exist before the apply run.

## Required Post-Apply Checks

After a real apply run, inspect the generated validator report before moving to
service activation:

```sh
cd ~/OSMAP
sed -n '1,120p' "$HOME/osmap-service-artifacts/<session>/reports/service-enablement-after-service-artifacts.txt"
```

The minimum expected result for this gate is the absence of all six
artifact-missing checks listed above.

The full service-enablement gate still has to be cleared separately through
`MAIL_HOST_SERVICE_ENABLEMENT_SOP.md`.

The current repo-owned host artifacts for this gate should be archived at:

- `maint/live/latest-host-service-artifact-session.txt`
- `maint/live/latest-host-service-enablement-report.txt`
