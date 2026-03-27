# Message List Slice Baseline

## Purpose

This document records the second implemented WP5 mailbox-read slice.

The goal of this slice is to prove that OSMAP can retrieve bounded per-mailbox
message summaries through the existing Dovecot surface while preserving the
validated-session boundary and avoiding premature adoption of a heavier IMAP
client stack.

## Status

As of March 27, 2026, the runtime now includes a message-list layer on top of
the completed auth, TOTP, session, and mailbox-listing baselines.

The current slice provides:

- a validated mailbox request model
- a message-list service that consumes a validated session
- a Dovecot-backed backend using `doveadm -f flow fetch`
- bounded parsing of flow-formatted message summary output
- structured message-list audit events for success and failure
- a live-host ignored test that safely exercises the missing-user path on
  systems with `doveadm`

This is the first message-list summary path, not a full message-view runtime.

The first message-view retrieval slice now exists too and is documented
separately in `MESSAGE_VIEW_SLICE_BASELINE.md`.

## Current Data Shape

The current message summary model intentionally stays narrow.

Each summary includes:

- mailbox name
- IMAP UID
- IMAP flags
- received-date string
- virtual size

This gives the runtime a concrete per-mailbox message index without yet taking
on message-body parsing, MIME rendering, or HTML-safety decisions.

## Security Boundary

Message-list retrieval does not perform its own authentication or session work.

The current layering is:

1. auth establishes a canonical user identity
2. TOTP verification completes the second-factor requirement
3. session validation establishes the active browser session
4. mailbox listing exposes available folders
5. message-list retrieval consumes a validated session plus a validated mailbox
   request

That separation matters because later HTTP handlers should stay consumers of
the identity and session layers rather than accidentally reimplementing them.

## Backend Choice

The current backend uses:

- `doveadm -f flow fetch`

with these fields:

- `uid`
- `flags`
- `date.received`
- `size.virtual`
- `mailbox`

Why this path was chosen:

- it stays close to the Dovecot authority already present on the OpenBSD host
- the `flow` formatter yields stable key/value records that are practical to
  parse without a large dependency
- it provides enough data for a first message list without forcing a message
  body or MIME design prematurely

The runtime is intentionally not claiming that this is the final long-term mail
access contract. It is the smallest honest message-summary baseline.

## Output Validation

The runtime currently validates:

- mailbox names from the backend
- presence of all required fields
- `uid` and `size.virtual` as unsigned integers
- received-date strings as bounded non-empty values
- flag strings as bounded non-control-character values
- total message count against an explicit maximum

These checks keep the runtime from blindly trusting external command output as
if it were already browser-safe application data.

## Logging And Audit Posture

The message-list slice emits structured events for:

- successful message-list retrieval
- message-list backend failure
- message-list output rejection

Current event fields include:

- canonical username
- session identifier
- mailbox name
- message count
- request identifier
- remote address
- user-agent summary

The success path records message count, not subject lines or message excerpts,
so the audit stream stays useful without becoming a content mirror.

## Validation Status

The current validation state is:

1. local unit and end-to-end tests completed
2. local integration-style tests now exercise auth, TOTP, session validation,
   mailbox listing, and message-list retrieval together
3. a live-host ignored test exists for the real `doveadm -f flow fetch`
   missing-user path on OpenBSD hosts with Dovecot available

This keeps the evidence narrow and safe while still grounding the backend
contract in the real OpenBSD target environment.

## What This Slice Proves

This slice now proves that:

- per-mailbox message summaries can be modeled behind the validated-session
  boundary
- the current Dovecot toolchain can provide a usable first message index
- message-list retrieval can stay dependency-light and auditable
- the project can continue toward message view and rendering without guessing
  about the read-path contract

## What Is Still Missing

This slice does not yet include:

- MIME structure handling
- HTML rendering policy
- attachment metadata or download handling
- pagination and sorting controls
- browser request handlers or templates

Those belong to the next WP6 and browser-facing slices rather than to this
message-summary baseline.
