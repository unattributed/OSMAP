# OpenBSD Runtime Confinement Baseline

## Purpose

This document records the first implemented OpenBSD-native runtime confinement
baseline for OSMAP.

The goal of this slice is to move confinement from design intent into a real,
operator-controlled runtime behavior while staying honest about the helper
processes and filesystem visibility the current prototype still depends on.

## Status

As of March 27, 2026, the runtime now recognizes:

- `OSMAP_OPENBSD_CONFINEMENT_MODE=disabled`
- `OSMAP_OPENBSD_CONFINEMENT_MODE=log-only`
- `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`

The `disabled` mode preserves the previous behavior.

The `log-only` mode emits the current promise and unveil plan without changing
runtime behavior.

The `enforce` mode on OpenBSD now:

- prepares a concrete `pledge(2)` promise set
- prepares a concrete `unveil(2)` ruleset from the validated runtime config
- applies the initial promise set that still allows `unveil(2)`
- unveils the current runtime paths and helper paths
- locks the unveil table
- drops the `unveil` promise from the steady-state process

This is the first enforced runtime boundary, not the final confinement story.

## Current Promise Model

The current enforced serve-mode process uses:

- `stdio rpath wpath cpath fattr inet proc exec unveil` before the unveil table
  is locked
- `stdio rpath wpath cpath fattr inet proc exec` after the unveil table is
  locked

This reflects the current application truth:

- serve HTTP on loopback TCP
- read and write bounded local state
- preserve restrictive permissions on session-state temp files during writes
- fork and execute helper programs
- keep the process small enough that the promise set remains reviewable

## Current Filesystem View

The current unveil plan includes:

- the configured OSMAP state root
- configured runtime, session, audit, cache, and TOTP-secret directories
- `/usr/local/bin/doveadm`
- `/usr/sbin/sendmail`
- `/usr/local/sbin/sendmail`
- `/usr/lib`
- `/usr/libexec`
- `/usr/local/lib`
- `/etc/dovecot`
- `/etc/mail`
- `/etc/mailer.conf`
- `/var/dovecot`
- `/var/log/dovecot.log`
- `/var/spool/postfix`
- `/var/spool/smtpd`
- `/dev/null`

This is still broader than the final target, but it is materially narrower than
the previous blanket `/etc` plus `/var` view because the current prototype now
has enough live-host evidence to describe helper dependencies more precisely.

## Why The View Is Still Broad

The current prototype does not yet implement IMAP, auth, or SMTP submission in
process. It still shells out to:

- `doveadm`
- `sendmail`

Those helpers inherit the parent process's unveiled filesystem view. That means
the first enforced unveil policy must remain broad enough for:

- system libraries
- helper-specific configuration files
- helper-specific runtime paths under `/var`

This is not the end goal. It is the smallest honest enforcement layer that can
be applied today without pretending the helper dependency problem is already
gone.

## Validation Status

The current confinement layer has been validated through:

- local Linux build and test verification, including the non-OpenBSD
  configuration path
- OpenBSD host `cargo test` on `mail.blackbagsecurity.com`
- OpenBSD host `serve` startup under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`
- OpenBSD host `GET /healthz` under enforced confinement
- live invalid-login handling under enforced confinement on
  `mail.blackbagsecurity.com`
- a synthetic session-gated attachment-route request under enforced confinement
  on `mail.blackbagsecurity.com`

The enforced OpenBSD run logged:

- startup report
- confinement plan
- confinement enabled
- HTTP server started
- successful health check handling
- successful synthetic session validation and refresh under `enforce`
- a bounded attachment-route failure for a missing user without the earlier
  Dovecot stats-writer socket noise

## Observed Caveat And Fix On `mail.blackbagsecurity.com`

A browser-driven invalid login smoke test on `mail.blackbagsecurity.com`
produced the same `doveadm auth test` backend failure both with confinement
disabled and with confinement enforced.

Follow-up diagnosis narrowed that result more precisely:

- OSMAP now passes `-o stats_writer_socket_path=` to the current `doveadm`
  auth, mailbox-list, message-list, and message-view helper calls
- live host validation now shows that this removes the previous
  stats-writer-socket permission noise from the mailbox and message-view helper
  paths under enforced confinement
- the remaining live auth issue on the host is the Dovecot auth-socket access
  boundary, not the stats writer and not the confinement mode itself

That distinction matters:

- confinement enforcement now exists and was exercised successfully
- the remaining live browser-auth caveat is now understood as a host/runtime
  user integration issue that still needs refinement before it can be called
  production-ready

Additional live validation also exposed and clarified two things:

- the session layer updates file permissions on temp session records during
  save, which requires `fattr` in the steady-state promise set
- the current host's accessible Dovecot auth surface for `foo` does not line up
  with the runtime's non-privileged browser-auth path today

The first point is already fixed in the promise set. The second remains an
active helper-integration caveat to narrow and validate further.

Today that auth caveat is understood this way:

- `doveadm auth test` without privilege still depends on an auth socket the
  runtime user can actually reach
- on `mail.blackbagsecurity.com`, the currently configured
  `/var/spool/postfix/private/auth` path is not accessible to an unprivileged
  runtime user because the directory boundary remains closed
- OSMAP should not solve that by widening its own privileges
- the right follow-on path is host-side operator work such as a dedicated
  accessible auth listener or a deliberate permission/layout change

The runtime now supports that operator path explicitly:

- `OSMAP_DOVEADM_AUTH_SOCKET_PATH` can point OSMAP at a dedicated Dovecot auth
  socket
- when configured, the OpenBSD confinement plan now adds the explicit socket
  path plus read-only parent-directory visibility for that path

That does not make the host issue disappear automatically, but it gives the
deployment model a concrete least-privilege target instead of a vague future
idea.

## What This Baseline Does Not Yet Claim

This baseline does not mean:

- the current unveil policy is narrow enough for final adoption
- helper-process dependencies have been eliminated
- browser auth is fully proven end to end on the target host
- richer send helper execution is fully proven under enforced confinement
- successful live attachment-bearing reads are fully proven under enforced
  confinement
- QEMU and host confinement validation are complete for every user workflow

The next confinement work should focus on narrowing the helper-compatible
filesystem view and proving more real user flows under enforced mode.
