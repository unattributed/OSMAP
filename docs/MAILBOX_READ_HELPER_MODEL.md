# Mailbox Read Helper Model

## Purpose

This document defines the selected next-step mailbox-read path for OSMAP.

The goal is to preserve least privilege on OpenBSD without teaching the
web-facing OSMAP runtime to depend on `doas` and without running the web-facing
service itself as `vmail`.

## Verified Problem

The current prototype reads mailbox data by invoking `doveadm` from the OSMAP
web process.

That is good enough for a bounded prototype, but current live-host validation on
`mail.blackbagsecurity.com` proves it is not a sufficient final shape for
least-privilege deployment there.

The relevant facts now verified are:

- OSMAP running as `_osmap` can authenticate successfully through a dedicated
  Dovecot auth listener
- OSMAP running as `_osmap` can also reach a dedicated Dovecot userdb listener
- the host Dovecot `user_query` still resolves mailbox access to
  `uid=2000(vmail)` and `gid=2000(vmail)`
- mailbox helpers run from the `_osmap` web process therefore fail on the
  current host when Dovecot tries to transition to the virtual-mail identity

This means the remaining blocker is not auth-socket reachability. It is the
mailbox-read identity boundary.

## Rejected Immediate Answers

The following answers are not the selected path:

- run the OSMAP web service as `vmail`
- let OSMAP use `doas` to cross the mailbox boundary
- make the Dovecot userdb socket world-accessible or otherwise broad enough to
  bypass reviewable least-privilege controls
- keep treating direct `doveadm` execution from the web process as the likely
  final shape

Each of those would reduce the clarity of the trust boundary or widen the
authority of the web-facing runtime more than necessary.

## Selected Path

The selected path is a dedicated mailbox-read helper boundary.

That means:

- the web-facing OSMAP service remains a dedicated unprivileged runtime such as
  `_osmap`
- mailbox-read operations move behind a local-only helper interface
- the helper can run under the mail-storage identity currently required by the
  host, such as `vmail`, without making the web service itself run that way
- the web service talks to the helper over a narrowly permissioned Unix-domain
  socket

This preserves a clear split between:

- the browser-facing policy and session service
- the mailbox-read execution context that must touch mail-storage authority

## Current Status

As of April 10, 2026, the first in-repo helper slice exists and has live-host
proof on `mail.blackbagsecurity.com`.

What is implemented:

- a dedicated `mailbox-helper` run mode
- a local Unix-domain socket helper server
- a small line-oriented request/response protocol
- helper-side peer-credential enforcement that only trusts the local caller
  identity derived from `OSMAP_DOVEADM_AUTH_SOCKET_PATH`
- a helper-backed mailbox-list client backend in the web runtime
- a helper-backed message-search client backend in the web runtime
- a helper-backed message-list client backend in the web runtime
- a helper-backed message-view client backend in the web runtime
- a helper-backed attachment-download client backend in the web runtime
- a helper-backed one-message move backend in the web runtime
- mailbox-list, message-search, message-list, message-view, attachment
  download, and one-message move routing through the helper when
  `OSMAP_MAILBOX_HELPER_SOCKET_PATH` is configured
- live helper-backed mailbox listing, message-list retrieval, message view, and
  attachment download under `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`, plus
  helper-backed search and one-message move in the browser runtime, with the
  web runtime kept as `_osmap` and the helper kept at the `vmail` boundary
- a dedicated Dovecot auth listener for `_osmap` plus a dedicated Dovecot
  userdb listener for the `vmail` helper path on the validated host

## Scope Of The Helper

The helper started as a read-oriented least-privilege boundary, but the current
Version 1 slice is now slightly broader than read-only.

Its currently implemented operations are:

- mailbox listing
- mailbox-scoped and all-visible-mailboxes search execution
- message-list retrieval
- single-message retrieval
- attachment-part retrieval needed for the current forced-download path
- one-message move between existing mailboxes

It should not take over:

- browser authentication
- session management
- outbound sendmail submission
- broad mailbox mutation workflows not yet implemented in OSMAP
- arbitrary command execution

## Request And Response Shape

The helper protocol should stay small and explicit.

Current request properties in the first slice:

- one explicit operation name
- canonical username
- mailbox name where required
- query text for message-search requests
- UID where required
- MIME part path where required
- destination mailbox name for one-message move requests

Current response properties:

- success or denied/error status
- bounded mailbox names for mailbox-list responses
- bounded message-search results for search responses
- bounded message summaries for message-list responses
- one bounded message payload for message-view responses
- one bounded attachment payload for attachment-download responses
- bounded move confirmation for one-message move responses
- operator-usable but bounded failure labels

The current wire format is a small line-oriented key/value protocol over a
Unix-domain socket. That is intentionally simpler than introducing a general RPC
framework in the first helper slice.

## Why A Helper Is Better Here

This path is preferred because it:

- keeps the web-facing process unprivileged
- avoids `doas` in the request path
- gives OpenBSD confinement a clearer target on both sides of the boundary
- isolates the mailbox-read authority that the current Dovecot virtual-user
  model still requires
- lets the current mailbox parsing and bounded-output logic be reused instead of
  replaced by a larger mail-access stack

## Expected OpenBSD Posture

The intended OpenBSD model is:

- `nginx` at the edge
- OSMAP web runtime as `_osmap`
- local-only mailbox helper over a Unix socket
- mailbox helper running under the mail-storage identity currently required by
  the host
- explicit socket permissions that allow `_osmap` to reach the helper and deny
  unrelated users
- helper-side peer-credential checks that still reject unrelated local callers
  even if filesystem socket permissions are widened incorrectly

The web runtime and the helper should each have their own `pledge(2)` and
`unveil(2)` plans instead of sharing one broad filesystem and execution view.

## Current Implementation Implication

The current direct `doveadm` integration remains acceptable as a development
and staging bridge because it already provides:

- bounded request validation
- bounded output parsing
- structured audit events
- a clear seam in code through mailbox backend traits

That seam is now the migration point for the helper-backed implementation.

As of the current Version 1 closeout baseline, production `serve` mode now
rejects configs that do not set `OSMAP_MAILBOX_HELPER_SOCKET_PATH`. That keeps
the helper boundary explicit in the first-release deployment posture instead of
leaving direct mailbox backends as an equally acceptable production path.

## First Helper Slice Outcome

The original first helper implementation target was to:

- live in this repository
- implement only read-only mailbox operations
- keep using the current bounded parsing model
- avoid introducing a heavyweight RPC framework
- run only on loopback or a Unix-domain socket
- ship with explicit OpenBSD service-management guidance

That did happen first, and the web-facing runtime switched from direct
`doveadm` execution to the helper one operation family at a time rather than
in one broad rewrite.

That migration is now underway:

- mailbox listing uses the helper when configured
- message search uses the helper when configured
- message-list retrieval uses the helper when configured
- message-view retrieval uses the helper when configured
- attachment download now uses a dedicated helper-side attachment operation
  when configured
- one-message move now uses the helper when configured
- first repo-owned OpenBSD service env examples for the split `_osmap` plus
  `vmail` runtime now live under `maint/openbsd/`
- `maint/live/osmap-live-validate-helper-peer-auth.ksh` now proves on
  `mail.blackbagsecurity.com` that trusted `_osmap` helper calls are accepted
  while an unrelated local caller is rejected by helper peer authorization

## What This Document Does Not Claim

This document does not claim that the helper is the final mailbox-read shape or
that every end-to-end browser flow is already proven.

It records the selected path and the first implemented slice so later work can
extend the helper boundary without widening the authority of the web-facing
process.

Follow-on live validation on `mail.blackbagsecurity.com` now also proves the
missing real-browser step for the current read path:

- real password-plus-TOTP login as the validation mailbox
- issued OSMAP browser session cookie
- helper-backed mailbox listing
- helper-backed message view
- helper-backed attachment download

That proof was exercised with the web runtime under `_osmap`, the helper under
`vmail`, and `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce`.
