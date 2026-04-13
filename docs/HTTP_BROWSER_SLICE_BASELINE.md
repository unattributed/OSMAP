# HTTP Browser Slice Baseline

## Purpose

This document records the next WP6 step after MIME-aware rendering:
actual HTTP/browser request handling.

The goal of this slice is to expose the existing auth, session, mailbox, and
message-read runtime through a small reviewable browser path instead of leaving
those capabilities as library-only primitives.

## Status

As of April 2, 2026, the runtime includes a dependency-light HTTP server and
browser router that can be started in `serve` mode.

The current slice provides:

- a bounded HTTP/1.x request parser
- a small bounded-concurrency TCP listener with one-request-per-connection
  behavior and an explicit in-flight connection cap
- explicit `bootstrap` and `serve` run modes
- browser routes for login, mailbox home, message lists, message view, compose,
  send, logout, and health checks
- session cookies with `HttpOnly` and `SameSite=Strict`
- CSRF tokens bound to persisted session state and required on current
  state-changing browser routes
- a bounded dual-bucket file-backed application-layer login-throttling slice
  for repeated browser auth failures
- strict response headers for cache suppression and content-security policy
- server-rendered HTML pages that consume the existing runtime layers instead
  of re-implementing them

This is intentionally smaller than a production web stack.

## Current Run Modes

The runtime now recognizes:

- `OSMAP_RUN_MODE=bootstrap`
- `OSMAP_RUN_MODE=serve`

The mailbox-read helper is documented separately in
`MAILBOX_READ_HELPER_MODEL.md` because it is a local support runtime rather
than a browser-facing mode.

`bootstrap` keeps the old behavior:

- validate configuration
- emit the startup report
- exit

`serve` does the same bootstrap work and then starts the current HTTP listener.

This split keeps operator checks and automated validation fast while still
making the browser slice runnable.

## Current Routes

The current browser layer provides:

- `GET /healthz`
- `GET /login`
- `POST /login`
- `GET /`
- `GET /mailboxes`
- `GET /mailbox?name=...`
- `GET /message?mailbox=...&uid=...`
- `GET /attachment?mailbox=...&uid=...&part=...`
- `GET /search?mailbox=...&q=...`
- `GET /compose`
- `GET /sessions`
- `GET /settings`
- `POST /send`
- `POST /message/move`
- `POST /sessions/revoke`
- `POST /settings`
- `POST /logout`

The routes intentionally mirror the current runtime baseline:

- login executes primary auth, TOTP verification, and session issuance
- mailbox home lists available mailboxes
- mailbox view lists message summaries
- message view consumes the existing safe renderer and attachment metadata
- message view can now also surface a bounded inline-image policy notice for
  HTML-capable messages whose surfaced attachment metadata includes inline image
  parts
- message view can now also surface bounded `Content-ID` metadata for
  attachment parts so the inline-image notice can distinguish likely
  `cid:`-backed assets from generic inline-disposition images
- attachment download reuses the existing session, message-view, and MIME
  attachment-part model
- search executes through the backend-authoritative mailbox search path instead
  of browser-side filtering
- compose renders the current plain-text-first outbound form, including
  reply/forward prefills when a source message is supplied
- the sessions page surfaces the current persisted-session metadata through a
  browser-safe view and allows self-service revocation
- the settings page surfaces the current bounded user preference for HTML
  display mode and allows CSRF-bound updates
- the message move route performs the current one-message folder-organization
  slice through the existing mailbox runtime
- send hands the composed message to the local submission surface
- logout revokes the current session token

## Browser Security Posture

The current browser slice follows these rules:

- keep request parsing bounded
- keep HTML server-rendered and small
- keep the session cookie `HttpOnly`
- keep the session cookie `SameSite=Strict`
- set `Secure` on the session cookie outside development
- require per-session CSRF tokens on current state-changing browser routes
- use `Cache-Control: no-store` on sensitive responses
- send a restrictive content-security policy
- send `Referrer-Policy: no-referrer`
- send `X-Content-Type-Options: nosniff`
- send `X-Frame-Options: DENY`
- send `Cross-Origin-Resource-Policy: same-origin` on current HTML, redirect,
  and attachment responses
- apply server-side credential-plus-remote and remote-only throttle checks
  before the auth backend is reached
- apply server-side canonical-user-plus-remote and remote-only throttle checks
  before the host submission surface is reached
- apply server-side canonical-user-plus-remote and remote-only throttle checks
  before the current one-message move workflow reaches the mailbox backend
- avoid JavaScript as a dependency for the first flow

This is not the final browser-security story, but it is an honest and useful
first boundary.

## Login Model

The first browser login page uses one form carrying:

- username
- password
- TOTP code

That is a UI simplification, not a security collapse.

Under the hood the runtime still performs:

1. bounded credential validation
2. primary credential verification
3. second-factor verification
4. session issuance

This keeps the implementation aligned with the already documented auth and
session boundaries while avoiding a larger multi-page state machine too early.

## What This Slice Proves

This slice now proves that:

- OSMAP can expose the current proof-of-concept runtime through a real browser
  path without a framework
- the existing auth, session, mailbox, and rendering layers are coherent enough
  to support a small end-to-end HTML flow
- the project can carry safe message rendering and attachment metadata all the
  way to a browser-facing page
- the browser layer can surface inline-image handling rules without widening
  sanitized HTML into a richer mail client
- the browser layer can surface bounded `Content-ID` metadata and use it to
  make inline-image policy messaging more precise without adding inline-image
  rendering
- the current outbound send path can be exposed through a bounded server-side
  compose form without inventing an SMTP client or rich browser runtime
- reply and forward behavior can be added as server-side draft generation
  without widening browser trust to HTML content or attachment upload
- CSRF controls can be added to the browser slice without reworking the core
  session model
- browser-visible session listing and revocation can be layered onto the
  existing persisted-session runtime without introducing a separate browser
  session subsystem
- a bounded end-user settings page can be layered onto the current runtime
  without becoming a broad preference platform
- bounded one-mailbox and all-mailbox search plus one-message move can be
  added as server-rendered browser routes without widening the client model
- a practical `serve` mode can exist without giving up the fast bootstrap-only
  validation path

## What Is Still Missing

This slice does not yet include:

- TLS termination inside OSMAP
- administrative routes
- broader auth-abuse and request-abuse controls beyond the current login and
  send throttling slices plus the first one-message move throttle slice
- broader live mutation-workflow coverage on the target host under confinement
- rich HTML mail behavior such as external resources, inline image rendering,
  or permissive styling support

The nginx-facing deployment model now has a matching implemented confinement
control. Live enforced-host proof now exists for the authenticated read path
plus the synthetic session-management routes, and the first bounded mutation
flows are now proven too: a one-message move and a send flow both succeeded on
`mail.blackbagsecurity.com` under `enforce`. The bounded send-throttle path is
now also live-proven there: one accepted `POST /send` followed by `429 Too
Many Requests` with `Retry-After` on the second matching submission. The
bounded message-move throttle path is now also live-proven there: one accepted
`POST /message/move` followed by `429 Too Many Requests` with `Retry-After` on
the second matching move. The bounded all-mailboxes search flow is now also
live-proven there: the mailboxes landing page rendered the global search form,
the mailbox page rendered the all-mailboxes search toggle, and a controlled
`/search?q=...` request returned hits from both `INBOX` and `Junk` in one
result set. Broader live-browser coverage still remains.
