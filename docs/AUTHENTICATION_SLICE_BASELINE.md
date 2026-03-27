# Authentication Slice Baseline

## Purpose

This document records the current WP3 implementation state for authentication.

The goal of this slice is not to complete the entire identity system. The goal
is to establish bounded credential handling, a clear primary-auth decision flow,
and audit-quality auth events before web or session complexity expands.

## Current Scope

The current authentication slice provides:

- bounded validation for submitted usernames and passwords
- bounded validation for auth-audit context such as request identifiers and
  remote addresses
- a primary credential backend interface
- a real Dovecot-oriented backend path using `doveadm auth test`
- a decision model that distinguishes denial from "MFA required"
- a second-factor verification stage
- structured auth events for successful and failed primary auth attempts
- structured auth events for successful and failed second-factor attempts
- a downstream session runtime that can consume authenticated-pending-session
  outcomes without collapsing auth and session logic together

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

The current second-factor slice can produce:

- request denied because the factor input was malformed
- request denied because the factor check failed
- request denied because the factor backend was unavailable
- request accepted to the extent that the user is now authenticated pending
  session issuance

The runtime now also has a session-management layer that can consume that
authenticated-pending-session outcome and issue a bounded browser session.

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

The event stream now includes separate actions for:

- primary login denied
- primary login backend failure
- primary login accepted with MFA required
- second factor denied
- second factor backend failure
- second factor accepted

## Security Posture

The auth slice follows these rules:

- passwords are not included in debug output
- credential fields are length-bounded
- malformed requests are denied before backend verification
- backend failures produce operator-visible audit events without pretending the
  auth attempt was normal
- primary auth acceptance leads to an MFA-required decision rather than an
  authenticated session
- second-factor success leads to an authenticated-pending-session decision, not
  a silent implicit session

## Current Backend Integration

The real primary credential verification path currently targets Dovecot through
`doveadm auth test`.

Why this path was chosen:

- it exists on the live OpenBSD mail host today
- it tests the actual Dovecot auth surface instead of a mock-only contract
- it can receive the password over standard input, which avoids putting the
  password on the command line
- it now suppresses the ancillary Dovecot stats-writer socket dependency in the
  helper invocation so auth errors stay closer to the real credential or socket
  boundary being exercised

The implementation treats:

- exit status `0` plus success output as primary acceptance
- exit status `77` or explicit auth-failure output as credential rejection
- other command failures as backend errors

This behavior is grounded in direct testing against `mail.blackbagsecurity.com`
and now has a project-local QEMU validation path prepared for broader isolated
verification.

## Validation Status

The current validation state is:

1. local unit and runtime verification completed
2. narrow OpenBSD host validation completed on `mail.blackbagsecurity.com`
3. project-local QEMU validation infrastructure is now present in
   `maint/qemu/` and syntax-checked, but a full VM boot-and-test run still
   remains pending in this workspace before higher-risk auth expansion

The host-side validation currently proves two bounded claims:

- the Rust auth slice builds and tests cleanly on the OpenBSD target host
- the live `doveadm auth test` backend rejects invalid credentials as expected

That is intentionally narrower than claiming the full auth workflow is already
validated in production-like conditions.

The remaining live-host caveat is also clearer now than it was earlier in WP3:

- the helper path no longer relies on the previous stats-writer socket behavior
  for its basic failure mode
- on `mail.blackbagsecurity.com`, the non-privileged runtime user still does
  not have the right Dovecot auth-socket access for the browser-auth path to be
  considered production-ready
- that is a host/operator integration issue to solve deliberately, not a reason
  to widen OSMAP's runtime privileges

The runtime now supports an explicit `OSMAP_DOVEADM_AUTH_SOCKET_PATH` setting
for hosts that provide a dedicated least-privilege Dovecot auth listener for
the OSMAP service user.

## What Is Still Missing

This slice does not yet include:

- auth rate limiting
- persistent auth-audit storage
- browser request handling
- cookie and CSRF policy
- recovery and enrollment UX

Those belong to the later browser-facing pieces of WP4 and WP5 rather than to
this authentication foundation slice.
