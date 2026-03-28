# Mailbox Listing Slice Baseline

## Purpose

This document records the first implemented WP5 mailbox-read slice.

The goal of this slice is to prove that OSMAP can retrieve a user's mailbox
list through the existing Dovecot surface without bypassing the session model
or introducing a large IMAP framework before the prototype actually needs one.

## Status

As of March 28, 2026, the runtime now includes a mailbox-listing layer that
operates behind the existing validated-session gate.

The current slice provides:

- a mailbox-listing service that consumes a validated session
- a Dovecot-backed backend using `doveadm mailbox list`
- bounded parsing of backend output into mailbox entries
- structured mailbox audit events for success and failure
- a live-host ignored test that safely exercises the missing-user path on
  systems with `doveadm`

This is the first mailbox read primitive, not a full mail UI.

The second WP5 slice now exists too: per-mailbox message-list retrieval is
documented separately in `MESSAGE_LIST_SLICE_BASELINE.md`.

## Security Boundary

Mailbox listing does not re-implement authentication or session validation.

The current layering is:

1. auth establishes a canonical user identity
2. TOTP verification completes the second-factor requirement
3. session issuance and validation establish the active browser session
4. mailbox listing consumes a previously validated session

That separation is deliberate. It keeps the mailbox layer from quietly becoming
its own identity system.

## Backend Choice

The current backend uses `doveadm mailbox list`.

Why this path was chosen:

- it stays close to the existing Dovecot authority for mailbox state
- it avoids committing to a large IMAP client dependency too early
- it is available on the real OpenBSD mail host already
- it is small enough to test, review, and replace later if needed

The current slice treats mailbox listing as a narrow control-plane read, not as
proof that the final message-view path has already been solved.

## Output Validation

The runtime currently validates backend output with conservative rules:

- mailbox names must not be empty
- mailbox names must remain length-bounded
- mailbox names must not contain control characters
- the total number of returned mailboxes must remain bounded

These checks are intentionally stricter than "accept whatever the backend
prints" because the browser-facing product should not inherit unreviewed output
shape from external commands.

## Logging And Audit Posture

The mailbox slice emits structured events for:

- successful mailbox listing
- mailbox backend failure
- mailbox-output rejection

Current event fields include:

- canonical username
- session identifier
- mailbox count
- request identifier
- remote address
- user-agent summary

The success path intentionally logs mailbox count rather than the full mailbox
name list so audit data stays useful without becoming a content dump.

## Validation Status

The current validation state is:

1. local unit and end-to-end tests completed
2. local integration-style tests now exercise auth, TOTP, session validation,
   and mailbox listing together
3. a live-host ignored test exists for the real `doveadm mailbox list`
   missing-user path on OpenBSD hosts with Dovecot available

The host validation model remains deliberately conservative: prove narrow,
safe claims first, then widen coverage as the browser and message-read paths
appear.

The live-host status is now more specific than it was when this slice was first
written:

- positive browser auth under `_osmap` is proven on `mail.blackbagsecurity.com`
- mailbox listing under `_osmap` is still not proven there
- the current blocker is Dovecot's virtual-mail identity model, not the auth
  socket path
- a dedicated userdb socket can be reached by `_osmap`, but the host's userdb
  lookup still resolves mailbox access to `uid=2000(vmail)` and
  `gid=2000(vmail)`, which an unprivileged `_osmap` process cannot assume

## What This Slice Proves

This slice now proves that:

- session-gated mailbox access can be modeled cleanly in code
- the current mail substrate can supply mailbox names through a small backend
- mailbox activity can be represented as structured audit events
- the project can keep moving without choosing a heavier mail-access dependency
  prematurely

## What Is Still Missing

This slice does not yet include:

- mailbox caching or pagination strategy
- a fully proven least-privilege mailbox-read path on
  `mail.blackbagsecurity.com` under `_osmap`

Message body retrieval, attachment handling, MIME policy, and the bounded
browser routes now exist elsewhere in the runtime. They remain outside this
mailbox-listing slice itself.
