# Folder Organization Slice Baseline

## Purpose

This document records the first bounded folder-organization slice in OSMAP.

The goal of this slice is not to reproduce the full ergonomics of a mature
webmail client. The goal is to provide one real, reviewable folder action that
supports ordinary mailbox organization without widening browser trust or
teaching the web-facing runtime to own mailbox-write authority directly.

## Status

As of March 28, 2026, the prototype now includes a first one-message move path
between existing mailboxes.

That slice currently covers:

- a validated `MessageMoveRequest` in the mailbox layer
- a backend-authoritative `doveadm move` execution path
- helper-backed move proxying when `OSMAP_MAILBOX_HELPER_SOCKET_PATH` is
  configured
- a CSRF-protected `POST /message/move` browser route
- a server-rendered move form on the message-view page
- bounded audit events for success and failure

This is a first usable folder-organization baseline, not the final mailbox UX.

## Current Behavior

The current move workflow is intentionally narrow:

- the user opens a message view
- the user submits one destination mailbox name
- OSMAP validates the source mailbox, destination mailbox, and UID
- the backend performs one `doveadm move`
- the browser redirects back to the source mailbox with a small success notice

Archive behavior currently uses this same path by moving a message into the
operator's chosen archive mailbox name.

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
   shape, service audit behavior, helper protocol parsing, and helper-backed
   client execution
2. browser-route tests cover the message-view move form, successful redirect,
   and source-mailbox success banner

Live-host mutation proof is still deferred. That should wait for a disposable
validation mailbox or other clearly safe host-side mutation harness rather than
touching ordinary user mail opportunistically.

## What Is Still Missing

This slice does not yet include:

- bulk move from mailbox-list pages
- archive shortcuts or archive mailbox discovery
- drag-and-drop or richer browser-side mailbox actions
- mailbox creation, rename, or deletion
- move-history visibility beyond the current audit log
- live-host move validation under `enforce`

Those belong to later workflow refinement rather than to this first bounded
folder-organization baseline.
