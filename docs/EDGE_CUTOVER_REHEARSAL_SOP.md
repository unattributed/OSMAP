# Edge Cutover Rehearsal SOP

## Purpose

This document is the operator procedure for rehearsing or applying the reviewed
OSMAP browser-edge cutover on `mail.blackbagsecurity.com` from the standard
host checkout at `~/OSMAP`.

It is paired with:

- `docs/EDGE_CUTOVER_PLAN.md`
- `maint/live/osmap-live-rehearse-edge-cutover.ksh`
- the reviewed host artifacts under `maint/openbsd/mail.blackbagsecurity.com/`

The goal is to keep the real cutover operationally scripted, not dependent on
manual file editing under pressure.

## Standard Host And Access Path

- host: `mail.blackbagsecurity.com`
- operator access: `ssh mail`
- standard checkout: `~/OSMAP`

## Standard Rehearsal Flow

1. Sync `~/OSMAP` to the reviewed `origin/main` snapshot.
2. Re-run the current Version 2 readiness gate if needed.
3. Run the host-side rehearsal wrapper:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-edge-cutover.ksh
```

The wrapper creates a timestamped session under `~/osmap-edge-cutover/` that
contains:

- `backup/` with the current live edge files copied from `/etc`
- `staged/` with the reviewed repo-owned replacements
- `scripts/apply-edge-cutover.sh`
- `scripts/restore-edge-cutover.sh`
- `edge-cutover-session.txt`

The rehearsal mode does not mutate the live edge. It prepares the exact
commands and the exact backup set for a later reviewed run.

## Standard Apply Flow

After reviewing the generated session contents:

```sh
ssh mail
cd ~/OSMAP
ksh ./maint/live/osmap-live-rehearse-edge-cutover.ksh --mode apply --session-dir "$HOME/osmap-edge-cutover/<session>"
```

That mode runs the generated `apply-edge-cutover.sh`, which performs:

- `doas install` of the reviewed nginx and PF files into `/etc`
- `doas nginx -t`
- `doas pfctl -nf /etc/pf.conf`
- `doas rcctl reload nginx`
- `doas pfctl -f /etc/pf.conf`

## Standard Restore Flow

If the cutover must be reversed:

```sh
ssh mail
sh "$HOME/osmap-edge-cutover/<session>/scripts/restore-edge-cutover.sh"
```

That script restores the backed-up files, removes `osmap-root.tmpl` when it
did not exist before the cutover, re-validates nginx and PF, and reloads both
control surfaces.

## Required Post-Apply Checks

After a real apply run, do not stop at config validation. Also run:

```sh
cd ~/OSMAP
ksh ./maint/live/osmap-live-validate-edge-cutover.ksh
ksh ./maint/live/osmap-live-assess-internet-exposure.ksh
```

If the candidate public edge is intended for real browser use, also re-run the
current Version 2 readiness wrapper and update `INTERNET_EXPOSURE_STATUS.md`
truthfully.
