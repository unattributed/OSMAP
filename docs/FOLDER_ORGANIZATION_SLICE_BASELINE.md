# Folder Organization Slice Baseline

## Purpose

This document records the first bounded folder-organization slice in OSMAP.

The goal of this slice is not to reproduce the full ergonomics of a mature
webmail client. The goal is to provide one real, reviewable folder action that
supports ordinary mailbox organization without widening browser trust or
teaching the web-facing runtime to own mailbox-write authority directly.

## Status

As of April 9, 2026, the prototype now includes a first one-message move path
between existing mailboxes plus a settings-backed archive shortcut that reuses
that same bounded mutation path.

That slice currently covers:

- a validated `MessageMoveRequest` in the mailbox layer
- a backend-authoritative `doveadm move` execution path
- helper-backed move proxying when `OSMAP_MAILBOX_HELPER_SOCKET_PATH` is
  configured
- a CSRF-protected `POST /message/move` browser route
- a server-rendered move form on the message-view page
- a user-configurable archive mailbox setting
- archive shortcut forms on the message-view page and mailbox-list rows when an
  archive mailbox is configured
- bounded audit events for success and failure

This is a first usable folder-organization baseline, not the final mailbox UX.

## Current Behavior

The current move workflow is intentionally narrow:

- the user opens a message view
- the user either submits one destination mailbox name manually or uses the
  configured archive shortcut
- OSMAP validates the source mailbox, destination mailbox, and UID
- the backend performs one `doveadm move`
- the browser redirects back to the source mailbox with a small success notice

Archive behavior now still uses this same path, but the mailbox name can be
stored once in the settings surface and reused through one-click archive forms
on message and mailbox-list pages.

## Authority Boundary

The selected authority model stays aligned with the existing least-privilege
mailbox-read helper work:

- when the mailbox helper socket is configured, the web runtime asks the local
  helper to perform the move
- the helper keeps the Dovecot-facing mailbox authority on the lower-privilege
  side of the boundary
- local and development paths may still use the direct backend when the helper
  is not configured

This keeps the first mutation slice from bypassing the authority split already
established for mailbox reads.

## Security Posture

The current slice keeps risk bounded by:

- requiring a validated browser session
- requiring a CSRF token on the state-changing route
- applying a bounded dual-bucket application-layer move throttle before the
  mailbox backend is reached
- validating both mailbox names before backend execution
- rejecting zero or malformed UIDs
- rejecting requests that try to move a message into the same mailbox
- delegating message movement to Dovecot rather than reimplementing mail
  mutation logic inside OSMAP

The browser still does not gain broad mailbox-write semantics. It gains one
small action that is mapped to an authoritative existing service.

## Validation Status

The current validation state is:

1. local unit coverage exists for request validation, `doveadm move` command
   shape, throttled rejection behavior, service audit behavior, helper
   protocol parsing, and helper-backed client execution
2. browser-route tests cover the message-view move form, settings-backed
   archive shortcut rendering on message and mailbox-list pages, successful
   redirect, and source-mailbox success banner
3. live-host mutation proof now exists on `mail.blackbagsecurity.com` under
   `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce` using a disposable validation
   mailbox, a synthetic validated browser session, and a controlled message
   injected into `INBOX`

That host proof confirms:

- the browser message-view page exposes the move form on the target host
- `POST /message/move` succeeds through the real browser route
- the helper-backed mailbox authority split remains intact under the `_osmap`
  plus `vmail` runtime boundary
- the controlled message is removed from `INBOX` and appears in `Junk`
- the bounded move throttle now also has live-host proof on the same target:
  one accepted move followed by `429 Too Many Requests` with `Retry-After` on
  the second matching move attempt

The repository now includes a reusable live-host harness for that proof at:

- `maint/live/osmap-live-validate-move-throttle.ksh`

## What Is Still Missing

This slice does not yet include:

- bulk move from mailbox-list pages
- archive mailbox discovery beyond the explicit user setting
- drag-and-drop or richer browser-side mailbox actions
- mailbox creation, rename, or deletion
- move-history visibility beyond the current audit log

Those belong to later workflow refinement rather than to this first bounded
folder-organization baseline.
