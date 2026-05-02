# Logging And Error Model

## Purpose

This document records the WP2 logging and error-handling baseline for the early
OSMAP prototype.

The goal is to establish useful operator diagnostics without adding a large
logging framework or leaking sensitive details.

## Logging Objectives

The current logging model is designed to:

- provide stable startup diagnostics
- keep event shape explicit and reviewable
- support later expansion into auth, session, HTTP, mailbox, and submission
  audit events
- remain dependency-light

## Current Event Shape

The bootstrap logger emits structured text lines containing:

- timestamp
- level
- category
- action
- message
- bounded key/value fields

This is intentionally simple. It is readable in a terminal and still structured
enough for later processing.

## Current Categories

The early logger currently distinguishes:

- `bootstrap`
- `config`
- `state`
- `http`
- `auth`
- `session`
- `mailbox`
- `submission`

This now covers the runtime foundation plus real browser, auth, session,
mailbox, and outbound-submission behavior.

## Sensitive Field Handling

Audit logs must support incident review without becoming a secondary secret
store.

Runtime audit events must not contain:

- browser session cookies
- raw session tokens
- raw persisted session lookup identifiers
- CSRF tokens
- passwords
- TOTP codes or TOTP secret material
- authorization headers
- message bodies
- attachment bodies

Session correlation uses `session_ref`, not `session_id`. `session_ref` is an
audit-only, domain-separated, truncated SHA-256 reference derived from the
internal persisted session identifier. It is deterministic enough to correlate
events for one session, but it must not be accepted as a browser cookie, session
filename, revocation target, or session lookup key.

`LogEvent::with_field()` defensively converts any attempted `session_id` audit
field into `session_ref`. Runtime call sites should still use `session_ref`
explicitly so code review does not depend only on the central safety net.

## Error-Handling Posture

The current bootstrap error model is intentionally handwritten and small.

It currently distinguishes:

- invalid configuration
- unsupported configuration values
- invalid state path boundaries

The purpose is to fail clearly and early when runtime assumptions are unsafe or
ambiguous.

## Non-Leaky Operator Errors

The current startup path follows these rules:

- operator-facing failures identify the configuration field that failed
- errors describe the violated rule
- errors do not print secret values because no secret-bearing settings are part
  of this slice
- startup exits cleanly on invalid bootstrap state rather than attempting hidden
  fallback behavior

Later runtime slices follow the same spirit:

- browser-visible failures use small stable messages
- audit events carry context without mirroring secrets or message bodies
- backend execution failures are translated into bounded user-facing outcomes

## Logging Level Model

The current runtime supports:

- `debug`
- `info`
- `warn`
- `error`

The logger applies simple minimum-level filtering so the event model remains
predictable before later subsystems start producing higher-volume output.

## Why No Logging Framework Yet

WP2 deliberately avoids adding a full logging stack at this stage because the
project still needs to prove:

- what the runtime actually does
- what events really matter
- which dependencies are justified

The early structured logger is enough to define the event shape without letting
tooling complexity outrun the implementation.

## Next Expansion Points

This model should evolve later to include:

- richer request-to-action correlation across mailbox and submission operations
- deployment-specific output routing on OpenBSD
- audit-log persistence and retention policy integration

Those should be added when real behavior exists, not preemptively.
