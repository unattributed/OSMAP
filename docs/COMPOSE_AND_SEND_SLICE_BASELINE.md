# Compose And Send Slice Baseline

## Purpose

This document records the first implemented outbound compose-and-send slice for
OSMAP.

The goal of this slice is to prove that the browser runtime can hand a small,
auditable outbound message to the existing mail-submission surface without
inventing a new SMTP client stack, without widening the browser trust model,
and without pretending rich mail composition is already solved.

## Status

As of March 27, 2026, the prototype now includes:

- a server-rendered compose page at `GET /compose`
- a state-changing send action at `POST /send`
- bounded validation for recipients, subject, and body
- a validated-session gate in front of the send path
- CSRF enforcement on the send form
- a local `sendmail` compatibility backend for handoff to the host mail stack
- structured submission audit events for success and failure

This is the first usable send path, not the final mail-composition feature set.

## Current Compose Shape

The current compose form accepts only:

- a simple comma-separated recipient list
- one subject line
- one plain-text body

The current shape intentionally excludes:

- attachments
- reply or forward helpers
- rich text
- arbitrary custom headers
- draft saving

This keeps the first send surface reviewable and easy to test.

## Validation Rules

The current compose path applies explicit bounds before it reaches the local
submission surface:

- recipients must parse as small addr-spec style mailbox values
- each recipient is length-bounded
- recipient count is capped
- subject length is capped and line breaks are rejected
- body length is capped

These rules make the first send slice boring in a good way: small inputs,
simple rejection paths, and no silent normalization of surprising values.

## Submission Model

The current outbound handoff uses:

- the validated session owner as the canonical sender identity
- the local `sendmail` compatibility surface at `/usr/sbin/sendmail`
- the arguments `-t -oi -f <canonical_username>`
- a simple RFC 5322-ish plain-text message shape

This keeps the submission path close to the host's existing mail authority
instead of duplicating SMTP behavior inside the application.

## Browser And Security Posture

The current send path preserves the existing browser/runtime security model:

- only an already validated session can reach compose or send behavior
- the send form includes a per-session CSRF token
- the send action rejects missing or invalid CSRF values
- the response remains server-rendered and dependency-light
- the composed body is treated as plain text, not browser markup
- failure responses are user-readable without exposing backend internals

The intent is to extend the current security posture, not bypass it for the
sake of feature momentum.

## Audit Model

The submission layer emits structured `submission` events for:

- accepted message handoff
- input rejection
- backend unavailability or execution failure

The success path records the canonical username and recipient count rather than
mirroring the full outbound message body into logs.

## Validation Status

This slice is currently validated through:

- local Rust unit tests for compose validation, sendmail handoff shape, and
  audit behavior
- local runtime verification through the existing `cargo` and `make lint`
  workflow
- OpenBSD host validation on `mail.blackbagsecurity.com`

The first send slice is therefore both implemented and exercised, but it is
still intentionally narrow.

## What Is Still Missing

This slice does not yet include:

- reply or forward behavior
- attachment upload or submission
- draft management
- message threading hints
- outbound rate limiting
- richer per-recipient validation policy
- operator-visible send queue or retry visibility

Those remain later send-path and operational-hardening work.
