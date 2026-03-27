# Authentication Slice Baseline

## Purpose

This document records the first WP3 implementation slice for authentication.

The goal of this slice is not to complete the entire identity system. The goal
is to establish bounded credential handling, a clear primary-auth decision flow,
and audit-quality auth events before web or session complexity expands.

## Current Scope

The current authentication slice provides:

- bounded validation for submitted usernames and passwords
- bounded validation for auth-audit context such as request identifiers and
  remote addresses
- a primary credential backend interface
- a decision model that distinguishes denial from "MFA required"
- structured auth events for successful and failed primary auth attempts

## Important Constraint

This slice intentionally does **not** claim the user is fully authenticated
after password verification alone.

When primary credentials are accepted, the current decision is:

- primary auth accepted
- second factor required

That keeps the runtime aligned with the project's MFA requirement instead of
quietly normalizing password-only success.

## Current Auth Outcomes

The current primary-auth slice can produce:

- request denied because the submitted input was invalid
- request denied because primary credentials were rejected
- request denied because the backend was unavailable
- request accepted only to the extent that MFA is now required

This is a more honest model than collapsing everything into "login success" or
"login failure" too early.

## Logging Posture

The current auth slice emits structured auth events that record:

- auth stage
- result
- request identifier
- remote address
- user-agent summary
- the submitted or canonical username as appropriate
- public and audit reasons for denied attempts

These events are intended to support later investigation of credential attacks
and unusual auth behavior.

## Security Posture

The auth slice follows these rules:

- passwords are not included in debug output
- credential fields are length-bounded
- malformed requests are denied before backend verification
- backend failures produce operator-visible audit events without pretending the
  auth attempt was normal
- primary auth acceptance leads to an MFA-required decision rather than an
  authenticated session

## What Is Still Missing

This slice does not yet include:

- real Dovecot or mail-stack credential verification
- TOTP verification
- session issuance
- auth rate limiting
- persistent auth-audit storage
- browser request handling

Those belong to the next pieces of WP3 and WP4 rather than to this foundation
slice.
