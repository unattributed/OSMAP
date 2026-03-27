# OpenBSD Runtime Confinement Baseline

## Purpose

This document records the first implemented OpenBSD-native runtime confinement
baseline for OSMAP.

The goal of this slice is to move confinement from design intent into a real,
operator-controlled runtime behavior while staying honest about the helper
processes and filesystem visibility the current prototype still depends on.

## Status

As of March 28, 2026, the runtime now recognizes:

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

- without a mailbox helper socket:
  `stdio rpath wpath cpath fattr inet proc exec unveil` before the unveil table
  is locked, then `stdio rpath wpath cpath fattr inet proc exec`
- with a mailbox helper socket:
  `stdio rpath wpath cpath fattr inet unix proc exec unveil` before the unveil
  table is locked, then `stdio rpath wpath cpath fattr inet unix proc exec`

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

When configured, the runtime also adds explicit read/write unveil rules for:

- `OSMAP_DOVEADM_AUTH_SOCKET_PATH`
- `OSMAP_DOVEADM_USERDB_SOCKET_PATH`

plus read-only visibility for their parent directory chains.

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
- OpenBSD host `log-only` serve startup under a dedicated `_osmap` runtime user
  and dedicated Dovecot auth listener
- OpenBSD host `serve` startup under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`
- OpenBSD host `GET /healthz` under enforced confinement
- live invalid-login handling under `log-only` confinement on
  `mail.blackbagsecurity.com`
- live invalid-login handling under enforced confinement on
  `mail.blackbagsecurity.com`
- live successful browser login under enforced confinement on
  `mail.blackbagsecurity.com`
- a synthetic session-gated attachment-route request under enforced confinement
  on `mail.blackbagsecurity.com`
- helper runtime startup under enforced confinement on
  `mail.blackbagsecurity.com`
- helper-backed mailbox listing, message-list retrieval, message view, and
  attachment download under enforced confinement on
  `mail.blackbagsecurity.com`

The enforced OpenBSD run logged:

- startup report
- confinement plan
- confinement enabled
- HTTP server started
- successful invalid-login handling under a dedicated least-privilege Dovecot
  auth listener in both `log-only` and `enforce`
- successful positive browser login plus TOTP completion under `_osmap` in
  `enforce`
- successful health check handling
- successful synthetic session validation and refresh under `enforce`
- successful helper-backed mailbox listing, message-list retrieval, message
  view, and attachment download under `enforce`

## Observed Caveat And Fix On `mail.blackbagsecurity.com`

A browser-driven invalid login smoke test on `mail.blackbagsecurity.com`
originally produced the same `doveadm auth test` backend failure both with
confinement disabled and with confinement enforced.

Follow-up diagnosis narrowed that result more precisely:

- OSMAP now passes `-o stats_writer_socket_path=` to the current `doveadm`
  auth, mailbox-list, message-list, and message-view helper calls
- live host validation now shows that this removes the previous
  stats-writer-socket permission noise from the mailbox and message-view helper
  paths under enforced confinement
- OSMAP now normalizes peer socket addresses to bare IP strings before building
  auth-helper metadata, which fixes the live `rip: Invalid ip` failure mode
- `mail.blackbagsecurity.com` now exposes a dedicated Dovecot auth listener at
  `/var/run/osmap-auth` for the `_osmap` runtime user
- live browser invalid-login validation now succeeds under both `log-only` and
  `enforce` with a true `invalid_credentials` result instead of a backend error

That distinction matters:

- confinement enforcement now exists and was exercised successfully
- the dedicated host-side auth-listener path is now proven viable without
  teaching OSMAP to depend on `doas`
- the dedicated host-side userdb-listener path is now also proven viable for
  the mailbox helper without widening the web-facing runtime

Additional live validation also exposed and clarified two things:

- the session layer updates file permissions on temp session records during
  save, which requires `fattr` in the steady-state promise set
- the target host's least-privilege runtime user can use a dedicated auth
  listener cleanly under confinement once the host configuration is aligned

The first point is already fixed in the promise set. The second is now resolved
for both invalid-login and positive-login validation on
`mail.blackbagsecurity.com`.

Today that auth caveat is understood this way:

- `doveadm auth test` without privilege still depends on an auth socket the
  runtime user can actually reach
- the validated host-side answer is a dedicated accessible auth listener rather
  than widening OSMAP's privileges or reusing the Postfix-facing socket
- on `mail.blackbagsecurity.com`, that listener is now `/var/run/osmap-auth`
  owned by `_osmap`
- mailbox and message helper paths can also be pointed at a dedicated userdb
  listener, now `/var/run/osmap-userdb` on `mail.blackbagsecurity.com`
- on the validated host, that userdb listener is now owned for the `vmail`
  helper path rather than for the `_osmap` web runtime

The runtime now supports that operator path explicitly:

- `OSMAP_DOVEADM_AUTH_SOCKET_PATH` can point OSMAP at a dedicated Dovecot auth
  socket
- `OSMAP_DOVEADM_USERDB_SOCKET_PATH` can point OSMAP at a dedicated Dovecot
  userdb socket for mailbox and message helper lookups
- when configured, the OpenBSD confinement plan now adds the explicit socket
  paths plus read-only parent-directory visibility for those paths

That now gives the deployment model a concrete least-privilege target instead
of a vague future idea, and the current host has live proof for it:

- `_osmap` handles browser auth through `/var/run/osmap-auth`
- the local mailbox helper handles mailbox reads through
  `/var/run/osmap-userdb` while running at the `vmail` boundary
- helper-backed mailbox and attachment reads succeed under
  `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`

## What This Baseline Does Not Yet Claim

This baseline does not mean:

- the current unveil policy is narrow enough for final adoption
- helper-process dependencies have been eliminated
- richer send helper execution is fully proven under enforced confinement
- authenticated mailbox, message-view, and attachment-bearing live-host reads
  are proven in one continuous real-login browser flow without synthetic
  session setup
- QEMU and host confinement validation are complete for every user workflow

The next confinement work should focus on narrowing the helper-compatible
filesystem view and proving more real user flows under enforced mode.

The now-selected next narrowing move is to stop treating direct mailbox helper
execution from the web process as the likely final shape. A dedicated local
mailbox-read helper boundary gives the confinement work a clearer target:

- the web-facing runtime can keep a smaller execution and filesystem view
- the mailbox helper can carry the narrower mail-storage authority it actually
  needs
- the two processes can be audited and confined separately

The helper-backed read-path migration now reaches mailbox listing,
message-list retrieval, message-view retrieval, and attachment-route source
message fetches when `OSMAP_MAILBOX_HELPER_SOCKET_PATH` is configured.
Helper-specific OpenBSD confinement now also exists as a distinct runtime plan
for `OSMAP_RUN_MODE=mailbox-helper`, with `unix` socket promises and a smaller
filesystem view than the browser-facing `serve` runtime.

That is still not the same thing as full live-browser coverage. The helper
runtime has now been exercised successfully on `mail.blackbagsecurity.com`
under the actual `vmail` boundary in this document's validation set, but
broader end-to-end coverage and further narrowing remain.
