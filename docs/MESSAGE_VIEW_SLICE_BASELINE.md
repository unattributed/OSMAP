# Message View Slice Baseline

## Purpose

This document records the first implemented WP6 message-view slice.

The goal of this slice is to prove that OSMAP can retrieve one bounded message
payload behind the validated-session boundary without pretending that MIME
parsing, attachment handling, or browser rendering policy are already solved.

## Status

As of March 27, 2026, the runtime now includes a single-message retrieval layer
on top of the completed auth, TOTP, session, mailbox-listing, and message-list
baselines.

The current slice provides:

- a validated message-view request model using mailbox name plus IMAP UID
- a message-view service that consumes a validated session
- a Dovecot-backed backend using `doveadm -f flow fetch`
- bounded parsing of a single flow-formatted message record
- structured message-view audit events for success, not-found, and failure
- a live-host ignored test that safely exercises the missing-user path on
  systems with `doveadm`

This is the first message-fetch substrate, not the final browser rendering
pipeline.

The next rendering step now exists too and is documented separately in
`RENDERING_POLICY_BASELINE.md`.

## Current Data Shape

The current bounded message payload includes:

- mailbox name
- IMAP UID
- IMAP flags
- received-date string
- virtual size
- full header block as fetched text
- full body text as fetched text

That gives the runtime a real message-read contract while staying honest about
what is still missing. The current slice fetches text and metadata; it does not
yet define safe browser presentation for arbitrary mail content.

## Security Boundary

Message retrieval does not re-implement authentication, MFA, or session logic.

The current layering is:

1. auth establishes a canonical user identity
2. TOTP verification completes the second-factor requirement
3. session validation establishes the active browser session
4. mailbox listing and message-list retrieval expose mailbox structure
5. message-view retrieval consumes a validated session plus a validated mailbox
   and UID request

This keeps the message-view layer a consumer of the security boundary rather
than another place where access-control behavior might drift.

## Backend Choice

The current backend uses:

- `doveadm -f flow fetch`

with this field set:

- `uid`
- `flags`
- `date.received`
- `size.virtual`
- `mailbox`
- `hdr`
- `body`

Why this path was chosen:

- it stays close to the Dovecot authority already present on the OpenBSD host
- it extends the existing flow-parser approach rather than introducing a larger
  mail-access dependency immediately
- it gives the prototype a real message payload before browser rendering
  decisions expand the scope

The current backend is a bounded fetch contract, not a claim that the final
message-view implementation should remain exactly this shape forever.

## Output Validation

The runtime currently validates:

- mailbox names from the backend
- presence of all required fields
- `uid` and `size.virtual` as unsigned integers
- received-date strings as bounded non-empty values
- flag strings as bounded values
- header blocks as bounded text payloads
- body text as bounded text payloads
- exactly one returned record for the requested mailbox and UID

The parser explicitly rejects zero-result and multi-result cases rather than
silently guessing which message should be shown.

## Logging And Audit Posture

The message-view slice emits structured events for:

- successful message retrieval
- not-found message retrieval
- backend failure
- output rejection

Current event fields include:

- canonical username
- session identifier
- mailbox name
- IMAP UID
- request identifier
- remote address
- user-agent summary

The success path intentionally logs identifiers and context, not message
headers or body content.

## Validation Status

The current validation state is:

1. local unit and end-to-end tests completed
2. local integration-style tests now exercise auth, TOTP, session validation,
   message-list retrieval, and single-message fetch together
3. a live-host ignored test exists for the real `doveadm -f flow fetch`
   missing-user path on OpenBSD hosts with Dovecot available

That keeps the evidence grounded in the real Dovecot surface without widening
live-host testing into content reads prematurely.

## What This Slice Proves

This slice now proves that:

- one-message retrieval can be modeled behind the validated-session boundary
- the Dovecot toolchain can provide a bounded fetched message payload for the
  prototype
- not-found and malformed-output conditions can be represented honestly
- the project now has a real substrate for later rendering and attachment work

## What Is Still Missing

This slice does not yet include:

- MIME structure parsing
- attachment metadata or download handling
- browser-safe transformation of hostile message content
- inline image and external-resource policy
- browser request handlers or templates

Those belong to the later WP6 slices rather than to this first message-fetch
baseline.
