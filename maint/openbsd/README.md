# OpenBSD Service Guidance

## Purpose

This directory carries the first repo-owned OpenBSD operator scaffolding for
the split OSMAP runtime:

- one web-facing `serve` process
- one local-only `mailbox-helper` process
- one shared Unix socket boundary between them

The goal is to make the current Version 1 deployment shape reviewable and
repeatable without pretending packaging or `rc.d` integration is already final.

## Files

- `osmap-serve.env.example`
- `osmap-mailbox-helper.env.example`
- `libexec/osmap-serve-run.ksh`
- `libexec/osmap-mailbox-helper-run.ksh`
- `rc.d/osmap_serve`
- `rc.d/osmap_mailbox_helper`

These files are intentionally non-secret and are meant to be copied into
operator-managed paths such as `/etc/osmap/`, `/usr/local/libexec/osmap/`, and
`/etc/rc.d/`.

## Suggested Runtime Split

The current least-privilege OpenBSD posture is:

- `nginx` stays at the public TLS edge
- OSMAP `serve` runs as `_osmap`
- OSMAP `mailbox-helper` runs as `vmail`
- browser auth uses a dedicated Dovecot auth listener such as
  `/var/run/osmap-auth`
- mailbox helper lookups use a dedicated Dovecot userdb listener such as
  `/var/run/osmap-userdb`
- the browser runtime reaches the helper over one local Unix socket

The example env files in this directory use:

- `/var/lib/osmap` as the web runtime state root
- `/var/lib/osmap-helper` as the helper state root
- `/var/lib/osmap-helper/run/mailbox-helper.sock` as the shared helper socket

That keeps the mailbox helper's writable tree separate from the browser
runtime's state while still making the helper boundary explicit.

## Socket Ownership Expectations

The mailbox helper currently creates its Unix socket with mode `0660`.

That means operators should make the socket directory and socket ownership
story explicit. One conservative pattern is:

- own the helper state root by `vmail`
- put `_osmap` and `vmail` in one shared group used only for this socket
- make `/var/lib/osmap-helper` and `/var/lib/osmap-helper/run` searchable by
  that shared group

The important property is not one specific group name. It is that `_osmap`
can connect to the helper socket without giving unrelated users access.

## Service Startup Order

Start the helper before the web-facing runtime.

A conservative operator sequence is:

1. install the example env files into `/etc/osmap/` and adjust paths as needed
2. create the state directories with ownership that matches the selected
   runtime users and shared socket group
3. install the launcher and `rc.d` examples into their operator-managed paths
4. start `osmap_mailbox_helper`
5. confirm the helper socket exists at the configured path
6. start `osmap_serve`
7. keep nginx pointed at the loopback HTTP listener

The `rc.d` examples assume:

- `/usr/local/bin/osmap` is the installed OSMAP binary
- `/etc/osmap/osmap-serve.env` holds the browser-facing env file
- `/etc/osmap/osmap-mailbox-helper.env` holds the helper env file
- `/usr/local/libexec/osmap/` holds the launcher scripts

Those launchers source the env file and then execute one explicit OSMAP CLI
mode so the final process table stays readable as:

- `/usr/local/bin/osmap serve`
- `/usr/local/bin/osmap mailbox-helper`

That keeps `rc.d` supervision and `pgrep` matching more honest than a generic
shell wrapper name alone.

## Validation Notes

The quickest local checks after wiring the env files are:

- run `OSMAP_RUN_MODE=bootstrap` with the same production env to confirm config
  validity before daemon startup
- or use the example `rc.d` scripts' `configtest` action after installation
- check that the helper socket appears at the configured path
- check that `_osmap` can connect to that socket without needing broader mail
  storage authority
- keep `OSMAP_OPENBSD_CONFINEMENT_MODE=log-only` for first host dry runs, then
  move to `enforce`

For repo-owned live-host validation commands, use
`maint/live/osmap-host-validate.ksh` from the standard host checkout.
