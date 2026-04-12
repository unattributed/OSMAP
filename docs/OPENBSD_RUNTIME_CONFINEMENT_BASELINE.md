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

The current unveil plan now differs meaningfully between the browser runtime
and the mailbox helper.

Shared runtime paths still include:

- the configured OSMAP state root, now as a read-only anchor path
- configured runtime, session, audit, cache, and TOTP-secret directories where
  the current mode needs them
- `/dev/null`

The current `serve` runtime is now narrower and more explicit on the validated
host too:

- the current `doveadm` auth-side dependency view:
  `/usr/local/bin/doveadm`, `/usr/local/bin/doveconf`,
  `/usr/libexec/ld.so`, exact resolved shared-library files where available,
  `/usr/local/lib/dovecot`, `dovecot.conf`, `conf.d`, `local.conf`, and
  `/var/dovecot/config`
- the current local sendmail path:
  `/usr/sbin/sendmail`, `/usr/local/sbin/sendmail`, and
  `/usr/local/sbin/postdrop`
- sendmail wrapper and Postfix config paths:
  `/etc/mailer.conf`, `/etc/postfix/main.cf`, `/etc/pwd.db`, `/etc/group`,
  `/etc/localtime`, `/usr/share/zoneinfo/posixrules`, `/dev/urandom`, and
  `/var/spool/postfix`

The current `mailbox-helper` runtime is now narrower and more explicit on the
validated host:

- `/usr/local/bin/doveadm`
- `/usr/local/bin/doveconf`
- `/usr/libexec/ld.so`
- exact resolved `doveadm` shared-library paths from `/usr/lib` and
  `/usr/local/lib` when the current host exposes the expected versioned files
- `/usr/local/lib/dovecot`
- `/etc/dovecot/dovecot.conf`
- `/etc/dovecot/conf.d`
- `/etc/dovecot/local.conf`
- `/var/dovecot/config`

If a host does not expose the expected exact versioned library filenames, the
helper falls back to the broader `/usr/lib` or `/usr/local/lib` visibility
instead of failing only because the host library naming differs.

When configured, the runtime also adds explicit read/write unveil rules for:

- `OSMAP_DOVEADM_AUTH_SOCKET_PATH`
- `OSMAP_DOVEADM_USERDB_SOCKET_PATH`

plus read-only visibility for their parent directory chains.

Follow-on live validation now also shows that the serve and helper runtimes do
not need direct unveil access to `/var/dovecot` or `/var/log/dovecot.log` for
the current auth, mailbox, message-view, and attachment-read workflows. Those
paths have therefore been removed from the active confinement plan.

## Why The View Is Still Broad

The current prototype does not yet implement IMAP, auth, or SMTP submission in
process. It still shells out to:

- `doveadm`
- `sendmail`

Those helpers inherit the parent process's unveiled filesystem view. That means
the current enforced unveil policy must still remain broader than the final
target in at least these places:

- the `serve` runtime still depends on the current Dovecot and Postfix helper
  shape rather than an in-process mail stack
- the helper still depends on the current Dovecot config socket and dynamic
  library layout
- the browser runtime still needs local submission spool paths and a
  mailwrapper-to-Postfix handoff

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
- helper-backed all-mailboxes browser search under enforced confinement on
  `mail.blackbagsecurity.com`
- helper-backed bounded message move under enforced confinement on
  `mail.blackbagsecurity.com`
- real password-plus-TOTP browser login plus one real browser send under
  enforced confinement on `mail.blackbagsecurity.com`
- one continuous real browser flow under enforced confinement on
  `mail.blackbagsecurity.com`, from password-plus-TOTP login through
  helper-backed mailbox, message-view, and attachment reads

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
- successful helper-backed all-mailboxes browser search under `enforce`
- successful helper-backed bounded message move and move-throttle handling
  under `enforce`
- successful real browser login plus one real browser send under `enforce`
- successful real browser session issuance followed by helper-backed mailbox,
  message-view, and attachment reads under `enforce`

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
- a real browser login can carry an issued session into those same helper-
  backed reads under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`

## What This Baseline Does Not Yet Claim

This baseline does not mean:

- the current policy is package-ABI-independent or free of conservative
  library fallbacks
- helper-process dependencies have been eliminated
- repo-owned split-runtime scaffolding is finished packaging or ports
  integration
- every possible host and user workflow has live proof under enforced
  confinement

The repository now treats the helper boundary plus the current serve-side auth
and sendmail dependency narrowing as the deliberate Version 1 stopping point.
The closeout discipline for that boundary is therefore to keep the release gate
and status docs aligned with the successful April 11, 2026 full host rerun,
rerun the affected repo-owned host proofs when it changes, and not reopen
direct mailbox authority from the web runtime as the likely production shape.

The helper-backed read-path migration now reaches mailbox listing,
message-list retrieval, message-view retrieval, attachment download, search,
and the first one-message move path when
`OSMAP_MAILBOX_HELPER_SOCKET_PATH` is configured. Helper-specific OpenBSD
confinement now also exists as a distinct runtime plan for
`OSMAP_RUN_MODE=mailbox-helper`, with `unix` socket promises, a smaller
filesystem view than the browser-facing `serve` runtime, and a read-only
top-level state-root anchor plus explicit writable child directories.

That is still not the same thing as full live-browser coverage. The helper
runtime has now been exercised successfully on `mail.blackbagsecurity.com`
under the actual `vmail` boundary in this document's validation set, and the
core authenticated read path is now proven in one continuous browser flow. The
repo now also carries a real password-plus-TOTP login-plus-send proof under
`enforce`, while broader workflow coverage beyond the current proof set and
further packaging work remain later refinements rather than the first active
Version 1 blocker.

For operator reruns, the authoritative host-side closeout path remains
`ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` in the standard
`~/OSMAP` checkout, with
`sh ./maint/live/osmap-run-v1-closeout-with-temporary-validation-password.sh`
as the standard guarded answer when the selected step set includes
`login-send`. `./maint/live/osmap-run-v1-closeout-over-ssh.sh` remains
available when the validating workstation is off-host but can reach
`mail.blackbagsecurity.com`, and now delegates those `login-send` reruns to
the same host-side helper.
