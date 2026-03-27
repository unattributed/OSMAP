# HTTP Browser Slice Baseline

## Purpose

This document records the next WP6 step after MIME-aware rendering:
actual HTTP/browser request handling.

The goal of this slice is to expose the existing auth, session, mailbox, and
message-read runtime through a small reviewable browser path instead of leaving
those capabilities as library-only primitives.

## Status

As of March 27, 2026, the runtime now includes a dependency-light HTTP server
and browser router that can be started in `serve` mode.

The current slice provides:

- a bounded HTTP/1.x request parser
- a small sequential TCP listener with one-request-per-connection behavior
- explicit `bootstrap` and `serve` run modes
- browser routes for login, mailbox home, message lists, message view, compose,
  send, logout, and health checks
- session cookies with `HttpOnly` and `SameSite=Strict`
- CSRF tokens bound to persisted session state and required on current
  state-changing browser routes
- strict response headers for cache suppression and content-security policy
- server-rendered HTML pages that consume the existing runtime layers instead
  of re-implementing them

This is intentionally smaller than a production web stack.

## Current Run Modes

The runtime now recognizes:

- `OSMAP_RUN_MODE=bootstrap`
- `OSMAP_RUN_MODE=serve`

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
- `GET /compose`
- `POST /send`
- `POST /logout`

The routes intentionally mirror the current runtime baseline:

- login executes primary auth, TOTP verification, and session issuance
- mailbox home lists available mailboxes
- mailbox view lists message summaries
- message view consumes the existing safe renderer and attachment metadata
- compose renders the current plain-text-first outbound form
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
- the current outbound send path can be exposed through a bounded server-side
  compose form without inventing an SMTP client or rich browser runtime
- CSRF controls can be added to the browser slice without reworking the core
  session model
- a practical `serve` mode can exist without giving up the fast bootstrap-only
  validation path

## What Is Still Missing

This slice does not yet include:

- TLS termination inside OSMAP
- attachment download handlers
- reply or forward workflows
- attachment upload handling
- administrative routes
- concurrent request handling
- runtime `pledge(2)` and `unveil(2)` enforcement

The nginx-facing deployment model and early confinement plan now exist in the
project documentation, but those controls are not yet enforced by the running
binary itself.
